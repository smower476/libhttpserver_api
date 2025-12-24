FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y \
    build-essential cmake libpqxx-dev git libssl-dev
WORKDIR /app

RUN git clone https://github.com/yhirose/cpp-httplib.git /usr/local/include/httplib_git && \
    cp /usr/local/include/httplib_git/httplib.h /usr/local/include/
COPY . .
RUN cmake -B build && cmake --build build

FROM ubuntu:22.04
RUN apt-get update && apt-get install -y libpqxx-6.4 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/build/rest_server .
EXPOSE 8080
CMD ["./rest_server"]
