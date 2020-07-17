# Passive measurement with Zeek

For our passive measurements in research networks, we cannot release the dataset. We are bound by agreements with our data providers. We can only provide high-level statistics - as given in the paper.

We used the standard installation method as described on [zeek.org](https://zeek.org). The measurement pipeline is run on real-world traffic. Setting up a data collection pipeline on a larger Internet link will require some resources and time. If you want to start this collection in your own network, you will have to install Zeek on a suitable server, which gets a copy of the Internet traffic that you want to monitor. Zeek installation instructions are given at [https://docs.zeek.org/en/stable/install/install.html](https://docs.zeek.org/en/stable/install/install.html). Note: for larger Internet uplinks you will want to deploy Zeek in cluster mode and use AF_PACKET or PF_RING to distribute your traffic accross worker nodes.
