Fix `{"hostname":"f7a4fdc43df5","output":"21:03:54.081274282: Warning K8s Operation performed by user not in allowed list of users (user=<NA> target=<NA>/<NA> verb=<NA>  )","priority":"Warning","rule":"Disallowed K8s User","source":"k8s_admission","tags":["k8s"],"time":"2023-02-05T21:03:54.081274282Z", "output_fields": {"evt.time":1675631034081274282,"kar.target.name":null,"kar.target.resource":null,"kar.user.name":null,"kar.verb":null}}`

generally test somerules
deal with the todos everywhere, especially all the comments out admission rules
sems like none of the extractions in extract.go work but at least debugger works now
