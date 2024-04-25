#!/bin/bash

cd images
docker load --input pwn01_backend.tar
docker load --input pwn01_frontend.tar
cd ..

docker-compose up -d