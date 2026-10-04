# Branding

The TechDetechtives name, logo and colours used by the vulnerability dashboard live here and in `config/techdetechtives.env`.

| What | Where | Default |
| --- | --- | --- |
| Logo | `branding/logo.svg` | The TechDetechtives mark: fingerprint ridges that end in circuit pads |
| Name | `TD_BRAND_NAME` | `TechDetechtives` |
| Header band colour | `TD_BRAND_HEADER` | `#14213d` (ink navy) |
| Accent colour | `TD_BRAND_ACCENT` | `#2ec4b6` (teal) |

The name appears in the header, the browser tab, the footer and the sign-in prompt. The logo appears in the header and as the tab icon.

## Using your own logo

1. Put the file in this folder. SVG is best; PNG, JPG and WebP also work. Keep it under 512 KB and roughly square, since it is shown at 30 by 30 pixels.
2. If the file is not called `logo.svg`, set `TD_BRAND_LOGO=/brand/<file name>` in `config/techdetechtives.env`.
3. Re-run `scripts/install.sh vulnerability` on the ticketing machine.

If the file is missing, too large or of another type, the dashboard falls back to the built-in mark rather than showing a broken image.

## Changing the colours

Set `TD_BRAND_HEADER` and `TD_BRAND_ACCENT` to colours written as `#rrggbb`, then re-run the install command. The header text switches between white and near-black by itself to stay readable on the band colour you choose. Pick an accent that stands out against the band.

Keep brand colours away from the reds and oranges: those carry severity in the charts.

## What is not rebranded

- **The Security Onion console** keeps its own logo and licence notices. The Elastic License 2.0 forbids removing the licensor's notices, and its name and logo are registered trademarks. The login banner and overview page carry the TechDetechtives name instead (`platform/branding/`).
- **DFIR-IRIS and Greenbone** run unmodified with their own interfaces.

The logo in this folder is original work for this project, under the repository's MIT licence.
