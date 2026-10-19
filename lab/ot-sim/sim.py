"""
TechDetechtives lab OT simulators — targets for the OT rules in
platform/detections/validation.yml (ot_network_checks). Lab use only.

  Modbus/TCP server   502    answers Read Device Identification (43/14)
  Siemens S7 server   102    snap7 server; accepts the PLC STOP request
  DNP3 outstation     20000  accepts the connection (stand-in: reads and discards)
  Experion eng. port  55553  listener for the folder-path test (rules 1900186/1900182)
  Experion eng. port  55555  listener for the program-code test (rule 1900184)

Each service is optional; failures are logged and the others keep running.
"""
import logging
import os
import socket
import threading
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ot-sim")


def sink(port, name):
    """Accept TCP connections and discard what is sent (protocol stand-in)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(16)
    log.info("%s listening on %d", name, port)

    def handle(conn, addr):
        total = 0
        with conn:
            conn.settimeout(30)
            try:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    total += len(data)
            except OSError:
                pass
        log.info("%s: %s sent %d bytes", name, addr[0], total)

    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


def modbus():
    from pymodbus.datastore import (ModbusSequentialDataBlock, ModbusServerContext,
                                    ModbusSlaveContext)
    from pymodbus.device import ModbusDeviceIdentification
    from pymodbus.server import StartTcpServer

    store = ModbusSlaveContext(di=ModbusSequentialDataBlock(0, [0] * 100),
                               co=ModbusSequentialDataBlock(0, [0] * 100),
                               hr=ModbusSequentialDataBlock(0, [17] * 100),
                               ir=ModbusSequentialDataBlock(0, [42] * 100))
    context = ModbusServerContext(slaves=store, single=True)
    ident = ModbusDeviceIdentification(info_name={
        "VendorName": "TechDetechtives Lab", "ProductCode": "TD-PLC-SIM",
        "VendorUrl": "https://techdetechtives.com", "ProductName": "Lab Modbus PLC",
        "ModelName": "SIM-502", "MajorMinorRevision": "1.0.0"})
    log.info("Modbus/TCP listening on 502")
    StartTcpServer(context=context, identity=ident, address=("0.0.0.0", 502))


def s7():
    import ctypes
    import snap7

    server = snap7.server.Server()
    db = (ctypes.c_uint8 * 256)()
    server.register_area(snap7.types.srvAreaDB, 1, db)
    server.start(tcpport=102)
    log.info("S7 (snap7) listening on 102")
    while True:
        time.sleep(5)
        try:
            ev = server.pick_event()
            while ev:
                log.info("S7 event: %s", server.event_text(ev))
                ev = server.pick_event()
        except Exception:  # noqa: BLE001
            pass


def run(name, fn, *args):
    def wrapper():
        while True:
            try:
                fn(*args)
            except Exception as e:  # noqa: BLE001
                log.error("%s stopped: %s (restarting in 10 s)", name, e)
                time.sleep(10)
    threading.Thread(target=wrapper, name=name, daemon=True).start()


if __name__ == "__main__":
    enabled = set(os.environ.get("OT_SIMS", "modbus,s7,dnp3,experion").split(","))
    if "modbus" in enabled:
        run("modbus", modbus)
    if "s7" in enabled:
        run("s7", s7)
    if "dnp3" in enabled:
        run("dnp3", sink, 20000, "DNP3 outstation stand-in")
    if "experion" in enabled:
        run("exp-55553", sink, 55553, "Experion engineering port 55553")
        run("exp-55555", sink, 55555, "Experion engineering port 55555")
    while True:
        time.sleep(3600)
