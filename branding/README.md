# Branding

The TechDetechtives artwork, and where each file is used.

| File | Size | Used for |
| --- | --- | --- |
| `banner.png` | 960 x 820 | The full emblem with the wordmark. Shown at the top of the repository README. |
| `banner-480.png` | 480 x 410 | The same emblem, smaller. Shown at the top of the platform's overview page. |
| `logo.png` | 256 x 256 | The square mark (detective and magnifier). Header logo and browser tab icon of the vulnerability dashboard. |
| `avatar.png` | 500 x 500 | Square emblem for the GitHub account picture. |
| `social-preview.png` | 1280 x 640 | The image GitHub shows when the repository link is shared. |

The artwork was supplied by the project owner. Its wordmark was re-lettered to the project's spelling, TechDetechtives, using the artwork's own letters. The original also showed the logos of other products around the emblem. These files leave those out: they are other organisations' trademarks, and a project logo that contains them would suggest an affiliation that does not exist (see `NOTICE.md`).

## Where the brand appears

- **GitHub:** the README banner comes from this folder. The account picture and the social preview are set by hand in GitHub's settings, using `avatar.png` and `social-preview.png`.
- **Vulnerability dashboard:** logo, name and colours in the header band, the tab icon, the footer and the sign-in prompt.
- **Platform console:** the emblem at the top of the overview page, and the name on the login banner and overview page.

## Dashboard settings

Set in `config/techdetechtives.env`, then re-run `scripts/install.sh vulnerability` on the ticketing machine.

| Setting | What it controls | Default |
| --- | --- | --- |
| `TD_BRAND_NAME` | Name in the header, tab, footer and sign-in prompt | `TechDetechtives` |
| `TD_BRAND_LOGO` | Logo file in this folder, written as `/brand/<file name>` | `/brand/logo.png` |
| `TD_BRAND_HEADER` | Header band colour, as `#rrggbb` | `#0b0b0d` (black) |
| `TD_BRAND_ACCENT` | Accent line colour, as `#rrggbb` | `#f60411` (the emblem's red) |

A logo file can be SVG, PNG, JPG or WebP, up to 512 KB, roughly square. If it is missing or unusable the dashboard falls back to a built-in mark rather than showing a broken image. The header text switches between white and near-black by itself to stay readable on the band colour.

The brand red sits close to the reds that carry severity in the charts. It is used only in the header band, where no chart can be mistaken for it.

## The image on the platform's overview page

The platform console can only show images that the analyst's browser fetches from another host, so the overview page loads `banner-480.png` from the public repository. Two consequences:

- Analysts' browsers need internet access for the image to appear. Without it the page shows a broken-image icon.
- Each page view makes a request to GitHub.

To host the image somewhere else, or to leave it out, re-apply the overlay on the manager:

```bash
sudo scripts/install.sh platform --brand-image-url https://your-internal-host/banner-480.png
sudo scripts/install.sh platform --brand-image-url none
```

## What is not rebranded

- **The Security Onion console** keeps its own logo and licence notices. The Elastic License 2.0 forbids removing the licensor's notices, and its name and logo are registered trademarks.
- **DFIR-IRIS and Greenbone** run unmodified with their own interfaces.
