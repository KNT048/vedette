# fix/zap-fence-nft (#765), deferred

- 2026-11-14 review r1 L3 (LOW): no test checks that the refused fence step's stderr/stdout reach the box log (a zapWorld case with a fake nft load exit 1 + stderr and a captured TextHandler, like hostports_test.go:412). Open.
