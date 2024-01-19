FROM golang:1.21

WORKDIR /app

COPY . ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /chall ./app/cmd

EXPOSE 8080

ENTRYPOINT ["/chall"]