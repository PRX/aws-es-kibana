FROM mhart/alpine-node:5.8

MAINTAINER PRX <sysadmin@prx.org>

ENV TINI_VERSION v0.9.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN chmod +x /tini

WORKDIR /app
EXPOSE 3000

ENTRYPOINT ["/tini", "--", "npm", "run-script"]
CMD [ "start" ]

ADD . ./

RUN npm set progress=false && npm install --unsafe-perm --loglevel error
