"""Missed-PR watchdog (cron backup): open PRs whose head has neither a guardian/scan status nor a Guardian run get submitted."""


class GH:
    def __init__(self, pulls, statuses):
        self.pulls, self.st = pulls, statuses

    def open_pulls(self, repo):
        return self.pulls

    def statuses(self, repo, sha):
        return self.st.get(sha, [])


def _pull(n, sha, draft=False, title="t"):
    return {"number": n, "draft": draft, "title": title, "head": {"sha": sha}, "base": {"sha": "a" * 40}}


def test_only_unscanned_non_draft_prs_without_a_run_are_submitted():
    from guardian.trigger.watchdog import missed
    gh = GH([_pull(1, "1" * 40), _pull(2, "2" * 40), _pull(3, "3" * 40), _pull(4, "4" * 40, draft=True)],
            {"1" * 40: [{"context": "guardian/scan", "state": "success"}], "2" * 40: [{"context": "ci", "state": "success"}]})
    runs = [{"repo": "me/app", "pr": 3, "head_sha": "3" * 40, "status": "running"}]
    ev = missed(gh, "me/app", runs)
    assert [e["pr"] for e in ev] == [2]
    assert ev[0]["action"] == "opened" and ev[0]["head_sha"] == "2" * 40 and ev[0]["wait"] is False and ev[0]["title"] == "t"
