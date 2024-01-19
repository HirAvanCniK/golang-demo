FROM golang:1.21

WORKDIR /app

COPY . ./

RUN GOOS=linux go build -o /chall ./auth/cmd

EXPOSE 8081

ENTRYPOINT ["/chall"]