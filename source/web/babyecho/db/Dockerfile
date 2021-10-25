FROM mongo
COPY ./mongo-import.sh /docker-entrypoint-initdb.d/
RUN mkdir /home/data
COPY ./flag.json /home/data

