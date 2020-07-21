FROM alpine:3.12

RUN apk add python3

COPY ./start.sh /start.sh
COPY ./main.py /main.py

RUN chmod 0744 /start.sh
RUN chmod 0744 /main.py

CMD ./start.sh
