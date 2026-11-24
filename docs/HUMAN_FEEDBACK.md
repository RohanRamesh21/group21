# Human feedback on Guardian findings

Use **Risk scores → select a finding → Finding review** to record how you assessed the evidence. Guardian keeps the reviews in a timeline and brings a finding back for review when its evidence changes or a deferral expires. The scanner and policy still determine the verdict, risk floors, and coverage requirements.

## Review a finding

| Action | Use it when | Record |
|---|---|---|
| **Confirm** | The scan evidence supports the finding | Your name and what you verified |
| **Challenge** | You disagree with the finding or one of its assumptions | Your name, the disputed claim, and a file or ticket reference if available |
| **Defer** | Someone needs to follow up by a specific date | Your name, rationale, owner, and due date in UTC |

Use **Save review** to add an entry. The card shows the latest disposition, and the timeline retains earlier decisions. Use **Reopened** above the findings list to see which reviews need another look. **Refresh** loads the latest saved scan without starting a new scan. **Download review** exports JSON with the current finding, current disposition, scan verdict, and the findings and rationale recorded at each review.

## When a review carries forward

- A review applies when the stable finding and its evidence still match. Package coordinates, advisory or detector, and source context distinguish findings. Source line numbers are locators, so a line move alone normally preserves a review.
- Guardian compares the recorded evidence with the new scan. Depending on the finding, this includes the component version and integrity, dependency path, reachability or exploitation status, detector evidence, or the base and head content digests for whole-file warnings. A difference reopens the finding. Daily score movements below an exploitation category change do not by themselves reopen a vulnerability review.
- A whole-file review recorded from an older report can reopen on the first rescan when Guardian adds the content digests.
- When multiple instances share an identity and Guardian cannot confidently match them across commits, it requires a fresh review. Findings that disappear from the current report leave the queue. Their earlier reviews stay in the database.
- A deferral remains current through its due date in UTC. An expired deferral or changed evidence shows **Reopened** the next time Risk scores loads. New advisory and exploitation data are picked up through a refreshed scan. Monitoring history is displayed separately.

## Storage and API

The dashboard server stores append-only events in `guardian-out/reviews.sqlite3`. History is scoped to the resolved local source path for CLI and local-path scans, the Git URL for remote scans, or the individual ZIP upload. Re-uploaded ZIPs start a new history. A review stores the full commit IDs, evidence digest, finding as presented in Risk scores, reviewer, rationale, timestamp, and deferral fields where applicable.

- `GET /api/scores` includes `review` on findings from scans with full head commit IDs. The object supplies `key`, `revision`, `status`, `reason`, and `latest_id`.
- `GET /api/reviews/{key}` returns the current finding and timeline. Add `download=true` for a JSON attachment. Use `project=<id>` for a dashboard scan. Omit it for the main CLI report.
- `POST /api/reviews/{key}` accepts `revision`, `previous_id` (or `null` for the first review), `action`, `reviewer`, and `rationale`. Include `owner` and `due_date` for `defer`. An outdated revision or timeline returns HTTP 409 so the reviewer can refresh before resubmitting.

Review notes are plain text stored by the local server. Reviewer and owner names are self-reported. A shared deployment needs authenticated identities and project permissions before exposing these endpoints. Review events are outside the agent prompt and the scanner’s policy inputs.

## Demonstrate the workflow

Use an approved local fixture with an undeclared `gdb` import. Challenge it with the rationale that GDB supplies the module to the pretty-printer. Move the import down without changing the detector evidence, commit, rescan with the same comparison mode, and refresh Risk scores. The challenge should still appear. Add another import that the detector counts, commit, and rescan again. The finding should show **Reopened**, with the original challenge in the timeline. Download the JSON to show both what the reviewer saw and the current evidence.

`tests/test_finding_reviews.py` exercises this sequence with simulated saved scan reports. It also checks expiry, repository scoping, stale submissions, and preservation of the machine verdict.
