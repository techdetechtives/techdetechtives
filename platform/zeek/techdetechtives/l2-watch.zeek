##! TechDetechtives layer 2 watch.
##! Copyright (c) 2026 TechDetechtives. MIT licence (see LICENSE).
##!
##! Watches which network card (MAC address) answers for which IP address, from
##! the ARP traffic the sensor receives, and raises a notice when that changes
##! in a way an attack would cause:
##!
##!   Address_Claimed_By_Two_Cards     two cards claim one address in turn (ARP poisoning, or two machines set to the same address)
##!   Address_Taken_Over               an address moved to another card while the first was still in use
##!   Address_Has_New_Card             an address moved to another card after the first went quiet
##!   Card_Answers_For_Many_Addresses  one card claims many addresses
##!   ARP_Reply_Burst                  one card keeps sending ARP answers nobody asked for
##!   ARP_Request_Flood                one card sends ARP requests at a high rate (sweep or storm)
##!   Many_New_Cards                   many card addresses never seen before, within a minute (MAC flooding)
##!   Software_Set_Card_Address        a new card whose address was set by software, not by its maker
##!
##! Notices are written to notice.log. The Sigma rules techdetechtives_l2_*.yml
##! turn them into alerts. The sensor must receive the ARP traffic of the network
##! segment: a mirror of a routed link shows only the routers' cards.
##!
##! This file is copied through the platform's template step, so it must not
##! contain two opening braces in a row, or an opening brace followed by a
##! percent or hash sign.

@load base/frameworks/notice

module TechDetechtives;

export {
	redef enum Notice::Type += {
		Address_Claimed_By_Two_Cards,
		Address_Taken_Over,
		Address_Has_New_Card,
		Card_Answers_For_Many_Addresses,
		ARP_Reply_Burst,
		ARP_Request_Flood,
		Many_New_Cards,
		Software_Set_Card_Address,
	};

	## Nothing is reported as "new" for this long after the first packet: at
	## start every card is new.
	option l2_learning_time = 10min;

	## An address that goes back to its earlier card within this time is being
	## claimed by two cards.
	option l2_flip_window = 10min;

	## A move counts as a takeover when the earlier card was seen this recently.
	option l2_takeover_window = 30min;

	## One card claiming this many addresses within five minutes is reported.
	option l2_many_addresses = 10;

	## Unasked ARP answers from one card, per minute.
	option l2_unasked_replies = 20;

	## ARP requests from one card, per minute.
	option l2_request_flood = 300;

	## Card addresses never seen before, per minute.
	option l2_new_cards = 100;

	## Report new cards whose address was set by software (virtual machines,
	## phones with private addresses, and address-changing tools all do this).
	option l2_report_software_set = T;

	## Cards and addresses that are left alone, for example a load balancer
	## that answers for many addresses, or a pair of firewalls sharing one.
	option l2_ignore_cards: set[string] = {};
	option l2_ignore_addresses: set[subnet] = {};

	## A card counts as known once it has been seen again this long after it
	## first appeared. Made-up cards are seen once and are forgotten after
	## half an hour, so a flood does not fill the memory for days.
	option l2_confirm_after = 2min;

	## Upper bound on each list that is remembered, so a flood of forged
	## addresses cannot exhaust memory.
	const l2_max_tracked = 100000 &redef;
}

type Owner: record {
	card: string;
	last_seen: time;
	previous: string &default="";
	changed: time &default=double_to_time(0.0);
};

global owners: table[addr] of Owner &read_expire=7day;
global known_cards: set[string] &read_expire=7day;
global fresh_cards: table[string] of time &create_expire=30min;
global card_addresses: table[string] of set[addr] &create_expire=5min;
global asked: set[addr, addr] &create_expire=5sec;
global unasked: table[string] of count &create_expire=1min &default=0;
global requests: table[string] of count &create_expire=1min &default=0;
global first_packet: time = double_to_time(0.0);
global new_card_window: time = double_to_time(0.0);
global new_card_count = 0;

function learning(): bool
	{
	if ( first_packet == double_to_time(0.0) )
		first_packet = network_time();
	return network_time() - first_packet < l2_learning_time;
	}

function usable(card: string): bool
	{
	return card != "" && card != "00:00:00:00:00:00" && card != "ff:ff:ff:ff:ff:ff" && card !in l2_ignore_cards;
	}

# The second hex digit of a card address says who set it: 2, 3, 6, 7, a, b, e
# and f mean it was set by software.
function software_set(card: string): bool
	{
	return /^.[2367abefABEF]/ in card;
	}

function saw_card(card: string)
	{
	if ( ! usable(card) )
		return;

	if ( card in known_cards )
		{
		add known_cards[card];    # refreshes its expiry
		return;
		}

	local now = network_time();

	if ( learning() )
		{
		if ( |known_cards| < l2_max_tracked )
			add known_cards[card];
		return;
		}

	if ( card in fresh_cards )
		{
		# Seen again a while after the first time: a real card.
		if ( now - fresh_cards[card] >= l2_confirm_after && |known_cards| < l2_max_tracked )
			{
			add known_cards[card];
			delete fresh_cards[card];
			}
		return;
		}

	# With the list full, a flood is under way and has been reported. Cards
	# that cannot be remembered are not counted either: a single one would
	# otherwise be counted again with every packet.
	if ( |fresh_cards| >= l2_max_tracked )
		return;
	fresh_cards[card] = now;

	if ( now - new_card_window > 1min )
		{
		new_card_window = now;
		new_card_count = 0;
		}
	++new_card_count;

	if ( new_card_count == l2_new_cards )
		NOTICE([$note=Many_New_Cards,
		        $msg=fmt("%d network card addresses never seen before appeared within a minute", new_card_count),
		        $sub=fmt("latest=%s", card),
		        $identifier="many-new-cards", $suppress_for=10min]);

	# Stop reporting single cards once a flood is under way.
	if ( l2_report_software_set && new_card_count < l2_new_cards && software_set(card) )
		NOTICE([$note=Software_Set_Card_Address,
		        $msg=fmt("New network card %s has an address set by software, not by its maker", card),
		        $sub=fmt("card=%s", card),
		        $identifier=card, $suppress_for=7day]);
	}

function learn(ip: addr, card: string)
	{
	if ( ip == 0.0.0.0 || ! usable(card) || ip in l2_ignore_addresses )
		return;

	local now = network_time();

	if ( card !in card_addresses && |card_addresses| < l2_max_tracked )
		card_addresses[card] = set();
	if ( card in card_addresses && ip !in card_addresses[card] && |card_addresses[card]| <= l2_many_addresses )
		{
		add card_addresses[card][ip];
		if ( |card_addresses[card]| == l2_many_addresses )
			NOTICE([$note=Card_Answers_For_Many_Addresses,
			        $msg=fmt("Network card %s has claimed %d addresses within five minutes", card, l2_many_addresses),
			        $sub=fmt("card=%s latest=%s", card, ip),
			        $src=ip, $identifier=card, $suppress_for=1day]);
		}

	if ( ip !in owners )
		{
		# Filled up by forged addresses: start again rather than stay blind to
		# every address that comes after. Poisoning is recognised from scratch
		# within a few of its own packets.
		if ( |owners| >= l2_max_tracked )
			clear_table(owners);
		owners[ip] = Owner($card=card, $last_seen=now);
		return;
		}

	local owner = owners[ip];
	if ( owner$card == card )
		{
		owner$last_seen = now;
		return;
		}

	local detail = fmt("address=%s now=%s before=%s", ip, card, owner$card);
	if ( card == owner$previous && now - owner$changed <= l2_flip_window )
		NOTICE([$note=Address_Claimed_By_Two_Cards,
		        $msg=fmt("%s is claimed by two network cards in turn: %s and %s", ip, owner$card, card),
		        $sub=detail, $src=ip, $identifier=cat(ip), $suppress_for=1hr]);
	else if ( now - owner$last_seen <= l2_takeover_window )
		NOTICE([$note=Address_Taken_Over,
		        $msg=fmt("%s moved from network card %s to %s while the first was still in use", ip, owner$card, card),
		        $sub=detail, $src=ip, $identifier=cat(ip), $suppress_for=1hr]);
	else
		NOTICE([$note=Address_Has_New_Card,
		        $msg=fmt("%s is now answered by network card %s (before: %s)", ip, card, owner$card),
		        $sub=detail, $src=ip, $identifier=cat(ip), $suppress_for=1hr]);

	owner$previous = owner$card;
	owner$changed = now;
	owner$card = card;
	owner$last_seen = now;
	}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	saw_card(SHA);
	learn(SPA, SHA);

	if ( SPA != TPA && |asked| < l2_max_tracked )
		add asked[SPA, TPA];

	if ( ! usable(SHA) || ( SHA !in requests && |requests| >= l2_max_tracked ) )
		return;

	++requests[SHA];
	if ( requests[SHA] == l2_request_flood )
		NOTICE([$note=ARP_Request_Flood,
		        $msg=fmt("Network card %s sent %d ARP requests within a minute (address sweep or storm)", SHA, l2_request_flood),
		        $sub=fmt("card=%s address=%s", SHA, SPA),
		        $src=SPA, $identifier=SHA, $suppress_for=1hr]);
	}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
	{
	saw_card(SHA);
	learn(SPA, SHA);

	# An answer to a question the sensor saw is normal. So is an announcement
	# (a card telling everyone its own address).
	if ( SPA == TPA || [TPA, SPA] in asked || ! usable(SHA) )
		return;
	if ( SHA !in unasked && |unasked| >= l2_max_tracked )
		return;

	++unasked[SHA];
	if ( unasked[SHA] == l2_unasked_replies )
		NOTICE([$note=ARP_Reply_Burst,
		        $msg=fmt("Network card %s sent %d ARP answers nobody asked for within a minute", SHA, l2_unasked_replies),
		        $sub=fmt("card=%s claims=%s told=%s", SHA, SPA, TPA),
		        $identifier=SHA, $suppress_for=1hr]);
	}

# The card that starts each conversation. This is what shows a MAC flood: the
# tools send packets from thousands of made-up cards.
event new_connection(c: connection)
	{
	if ( c$orig?$l2_addr )
		saw_card(c$orig$l2_addr);
	}
