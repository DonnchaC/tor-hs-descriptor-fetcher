# Automated HS Descriptor Fetch

This is a simple script to poll HSDir's for hidden service descriptors. Until HS descriptor fetching is merged into little-t-tor ([#14847](https://trac.torproject.org/projects/tor/ticket/14847)) you will need to be running dgoulets Tor branch.

    git clone https://git.torproject.org/user/dgoulet/tor.git
    cd tor && git checkout origin/bug14847_027_03

All unique descriptors are stored in the *descriptor/* directory.
