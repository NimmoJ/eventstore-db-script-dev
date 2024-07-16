FROM ubuntu:22.04

RUN apt-get update
RUN apt-get -y install curl
RUN apt-get -y install cron
RUN apt-get -y install software-properties-common
RUN apt-get -y install iproute2 

RUN echo '#!/bin/bash' > /usr/local/bin/sudo && \
    echo '$@' >> /usr/local/bin/sudo && \
    chmod +x /usr/local/bin/sudo

CMD /bin/bash