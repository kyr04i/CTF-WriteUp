PROJECT = pwn
COMPOSE_FILE = docker-compose.yml

.PHONY: install
install:
	sudo docker-compose -f $(COMPOSE_FILE) -p $(PROJECT) up -d --build

.PHONY: restart
restart:
	sudo docker-compose -f $(COMPOSE_FILE) -p $(PROJECT) kill && \
	sudo docker-compose -f $(COMPOSE_FILE) -p $(PROJECT) rm -f && \
	make install

.PHONY: shell
shell:
	sudo docker exec -u root -it calc /bin/bash