# TODO

- Improve spoofing model.
  - Simulate retransmissions probabilistically.
  - Keep attack flow sequence state and sometimes resend a previous sequence.
  - Make retransmission probability configurable.
  - Prefer payload-bearing attack packets that look like established data flows.

- Rename graph labels.
  - Replace "Servidor" with "Receptor" or "Destinatario".
  - Replace "Cliente" with "Emissor" or "Remetente".
  - Remove "(IPv4)" from base P4Drop graph titles where IPv4 is implicit.

- Review pcap-based metrics.
  - Decide whether plots should count all TCP packets or only payload-bearing TCP packets.
  - Confirm sent/received interfaces remain `s1-eth2_out.pcap` and `s1-eth1_in.pcap`.

- Add legitimate-delivery comparison plot.
  - Compare legitimate delivery with and without attack.
  - Start with `legitimate_received / legitimate_transmitted`.
  - Use the `mixed_0.0` run as the no-attack mixed-flow baseline.
  - Compare against `mixed_0.1`, `mixed_0.2`, and `mixed_0.5`.
  - Consider plotting normalized degradation: `delivery_with_attack / delivery_without_attack`.
