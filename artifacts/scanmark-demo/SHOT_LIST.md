# ScanMark: 30-second launch film shot list

**Format:** 30 s · 16:9 master at 3840×2160 (UI stills are captured at 3840×2160; phone stills at 1170×2532) · 24 fps.
**Brand:** ScanMark green `#005A2B` (mid `#007A3D`, light `#00A854`), gold `#FFD700`, navbar green `rgb(0,55,25)`, ink `#18242F`. Typeface **Poppins** (the app's own) at 600–800 for supers, 400 for small print.
**Logo:** `ScanMark/static/logo.png`, the QR-and-tick mark, as supplied. Pair it with the in-app wordmark: "Scan" in white or ink, "Mark" in gold. Do not redraw, recolour or animate the mark's internal modules into a different code.

### Reading the labels

| Label | Meaning |
|---|---|
| **VERIFIED** | Real ScanMark UI captured from the running app in this package. Reframing, 3D placement, depth of field, light sweeps and speed ramps are fine. Changing what the UI says or shows is not. |
| **CONCEPT** | Animation, live action or 3D with no product UI in it. Keep it free of numbers or claims about ScanMark. |
| **COMPOSITE** | Real UI captures arranged into a designed layout. Every UI element in frame must come from this package unaltered. |

**About the reference:** the supplied reference (`vimeo.com/1223791299`) could not be opened from the capture environment. Vimeo showed a verification wall and the oEmbed API returned `domain_status_code: 403`. The camera, light and pacing notes below follow the brief's own direction. Check them against the reference before locking the animatic.

---

## Beat 1 · 0:00–0:04 · Traditional attendance friction · CONCEPT

| # | Time | Picture | Camera / transition | Type | Sound |
|---|---|---|---|---|---|
| 1A | 0:00–0:01.5 | A paper sign-in sheet passes hand to hand along a crowded lecture-hall row, shot in shallow focus. Names crowd the margins. | Slow lateral dolly along the row. Low, warm practical light, with dust caught in a projector beam. | — | Room tone, paper rustle, a murmured roll call under it. |
| 1B | 0:01.5–0:03 | Macro: a pen runs dry mid-signature, then a second hand signs a name that isn't its own. | Snap-zoom into the nib. | — | Pen scratch, a dry stutter. |
| 1C | 0:03–0:04 | The sheet lands on a lecturer's desk on top of a stack of others. The light dims to near black and holds on the stack. | Top-down push-in, then fade the light. | Super: **"Attendance shouldn't take the lecture."** | A low sub swell builds. The room sound ducks out. |

The super is a statement of intent, not a statistic. Do not add time-saved or adoption figures; this package measured none.

## Beat 2 · 0:04–0:08 · Brand reveal · VERIFIED logo

| # | Time | Picture | Camera / transition | Type | Sound |
|---|---|---|---|---|---|
| 2A | 0:04–0:05.5 | From the black, the paper's projector beam resolves into a field of soft QR modules, which assemble into the real ScanMark mark (`logo.png`). | The modules converge with a slight Z-depth parallax. A single gold rim-light sweep crosses the mark. | — | Riser into a clean, glassy hit on the tick. |
| 2B | 0:05.5–0:08 | The mark settles left and the wordmark **Scan**_**Mark**_ types on in Poppins 800, with "Mark" in gold. The background is a deep green gradient (`#003719` to `#005A2B`). | Locked off, with a slow 102%→100% scale settle. | Tagline under it: **"Attendance in a scan."** | A soft UI "tick" on the gold. The music bed enters. |

## Beat 3 · 0:08–0:15 · Authentic QR check-in · VERIFIED

| # | Time | Picture | Source | Camera / transition | Sound |
|---|---|---|---|---|---|
| 3A | 0:08–0:10 | The lecturer's projector screen: "Scan to Mark Attendance", CSC 201, the live QR and "Classroom: Lecture Theatre 2 ✅". | `02-lecturer-session-qr.png`, or `09` 00:04–00:08 (the projector just opened, 0 / 24) | The UI plane floats in 3D at a ~12° Y-rotation. A slow push into the QR card. A gentle depth-of-field falloff on the navbar. | A projector fan hum and a light electronic pulse in time with the QR's 12 s refresh counter. |
| 3B | 0:10–0:11.5 | **Match cut:** the same projector card is now *inside the phone's camera viewfinder*. The green frame snaps around the code and the status reads "Marking attendance...". | `03-student-checkin.png`, or `08` 00:07.3–00:09.6 (the scanner with the projector's code in view) | Cut on the QR's position. The phone sits in a neutral device frame, tilted toward the lens, with a cool screen glow on the device edge. | A scanner chirp. A soft haptic thump on the frame lock. |
| 3C | 0:11.5–0:13 | Phone: **"Attendance marked successfully!"** | `04-attendance-confirmation.png`, or `08` from 00:09.8 (cut past the two black frames at 00:09.70) | A quick push-in on the banner, with a soft green bloom behind the phone (keep it subtle). | A bright confirmation tone, resolved on the beat. |
| 3D | 0:13–0:15 | Back on the projector, the "Present Today" list: **Tolu Adeyemi**, DEMO230001, lands at the top and the count reads 15 / 24. | `02b-lecturer-live-checkins.png`, or `09` 00:33–00:37 (the arrival lands at the top of the list, QR still in frame) | A split-screen, or a 3D two-up with the phone foreground left and the projector list background right, the phone's banner and the list row lit together. | A ripple of small ticks as other names arrive (they are in the footage). |

This beat is the film's proof, so keep it honest. The phone's camera feed *is* the projector screen captured by Playwright (see README, "How the camera works"). Do not composite a different QR into the viewfinder or replace the student's result with a different message.

## Beat 4 · 0:15–0:22 · Records and analytics · VERIFIED

| # | Time | Picture | Source | Camera / transition | Sound |
|---|---|---|---|---|---|
| 4A | 0:15–0:17.5 | The CSC 201 register: "9 classes held · 24 enrolled now · …", with today's session expanded and Tolu Adeyemi in the sheet. | `05-attendance-records.png`, `05b-attendance-records-full.png` (tall: for a vertical camera move) | A slow vertical crane down the full-page capture, past the per-session accordion. | Paper-to-glass whoosh, very light. |
| 4B | 0:17.5–0:20 | Course analytics: the "Daily Attendance Volume" line chart drawing across the term, with the Peak and Average tiles. | `06-dashboard-analytics.png`, `06b-dashboard-analytics-full.png`; the line draws on screen in `09` ≈ 01:12.7–01:14.2 | Use the real Chart.js draw-on from `09`. Rack focus from the tiles to the curve. A gold glint follows the line's last point. | A rising synth arpeggio that tracks the line. |
| 4C | 0:20–0:22 | The lecturer dashboard: CSC 201 / 205 / 211 cards and the "3 Total Classes · 2 Instructors" tiles. | `01-product-dashboard.png` | A wide pull-back that reveals the full dashboard as a floating 3D plane with soft shadow. | Music opens up. |

Use only the numbers on these screens, which `verification.json` checked against the database. Don't add percentages, trend arrows or AI insights the app doesn't show.

## Beat 5 · 0:22–0:27 · The value of an organised digital workflow · COMPOSITE

| # | Time | Picture | Camera / transition | Type |
|---|---|---|---|---|
| 5A | 0:22–0:24 | Three real UI cards fan out in depth: the projector QR (02), the phone confirmation (04), the session register (05). | A slow orbit with a single key light from the upper left and a cool fill. | **"Rotating QR codes."** |
| 5B | 0:24–0:25.5 | The "Classroom: Lecture Theatre 2 ✅" strip from 02, beside the phone. | A push-in to the classroom strip. | **"Checked against the classroom."** |
| 5C | 0:25.5–0:27 | The register (05) with the "📥 Semester Register (CSV)" and "🧾 Audit Trail" buttons in frame. | A slow lateral drift, then everything slides back to black. | **"Every class, its own register."** |

**What each super rests on (all verified in the code or the capture):**
- *Rotating QR codes*: the projector refreshes a signed token every 12 s (`QR_TOKEN_TTL`), visible as "Code refreshes in Ns" in 02.
- *Checked against the classroom*: with `GEOFENCE_REQUIRED` on (the default), scans are refused outside the saved room's radius. The demo scan was accepted 18 m from the pinned centre of a room with a 60 m radius.
- *Every class, its own register*: one sheet per class session, percentages against each session's roster snapshot, and CSV export and audit-trail buttons on the register page. The CSV and audit pages exist but weren't filmed. Show the buttons, not invented contents.

**Avoid:** "saves N hours", "100% accurate", "fraud-proof", "used by N universities", testimonials, or any partner logo. None of these is supported. The register is evidence of a scan, not of a body in a seat; the app's own code comments say so.

## Beat 6 · 0:27–0:30 · Logo end card · VERIFIED logo

| # | Time | Picture | Camera / transition | Type | Sound |
|---|---|---|---|---|---|
| 6A | 0:27–0:30 | The `logo.png` mark is centred on deep green with the wordmark **ScanMark** beneath it ("Mark" in gold). A thin gold rule draws under it left to right. | Locked off. One final light sweep across the mark at 0:28. Hold clean for the last 1.5 s. | Line 2 in Poppins 400, 60% white: **"Smart attendance, one scan at a time."** Add a URL or CTA only if the client supplies it. | The final hit on the tick (it echoes 2A), then a 1.5 s tail to silence. |

---

## Sound design summary

- **Palette:** an organic room (paper, pens, a murmur) for beat 1, then clean, glassy UI sounds and a restrained electronic bed from beat 2 on. No stock "cash register" dings.
- **Sync points:** the QR's refresh pulse (3A), the frame lock (3B), the success tone (3C), the arrival ticks (3D), the chart line (4B), the logo hits (2A, 6A).
- **Mix:** dialogue-free. Leave headroom for a VO. If a VO is added, its claims follow the same verified/concept rules as the supers.

## Hand-off checklist for the editor

- [ ] Every product shot comes from this folder. Nothing is rebuilt as a mock-up.
- [ ] No UI text, numbers or names are retouched. Crops, blur, light and 3D placement only.
- [ ] Synthetic data stays recognisable as such where legible (the `DEMO…` matric numbers and the "Section DEMO" label).
- [ ] Concept shots (beat 1) contain no ScanMark UI and no figures.
- [ ] The end card uses `ScanMark/static/logo.png` unaltered.
