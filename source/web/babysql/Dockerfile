FROM python
WORKDIR /srv
COPY ./ ./
RUN pip3 --no-cache-dir install -r requirements.txt
EXPOSE 1337
CMD python3 -m gunicorn --worker-tmp-dir /dev/shm --bind 0.0.0.0:1337 babysql:app
