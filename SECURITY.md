# Security

CityLink is a research harness. It has not been reviewed as a production protocol, and the commissioning files are ordinary JSON with filesystem permissions rather than a secure element.

Do not point the compose broker at a network you do not control. `deploy/mosquitto.conf` allows anonymous clients because the lab's confidentiality and authenticity claims are about the CityLink payload, not about MQTT authentication.

A cryptographically relevant quantum computer is not required to attack a deployment that uses this code as if it were TLS. For a real smart-city backhaul, use a maintained TLS 1.3 stack with a hybrid key-agreement group such as `X25519MLKEM768` (RFC 10024) and treat device identity, revocation, and key storage as a separate problem.

If you believe you have found a defect in the harness itself, open a GitHub issue with the suite name, the profile, and a failing test. Please do not file claims that CityLink should be deployed.
