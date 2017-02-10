PYTHON27 ?= $(shell which python2.7)
PYTHON35 ?= $(shell which python3.5)

default: test_prospector test_unit

test: test_prospector test_unit test_integration

venv/unit: PYTHON = $(PYTHON35)
venv/integration: PYTHON = $(PYTHON27)
venv/%: %/requirements.txt
	virtualenv -p "$(PYTHON)" "$@"
	"$@"/bin/pip install -r "$<"
	touch "$@"

test_prospector: venv/unit
	venv/unit/bin/prospector --no-autodetect \
	    ../templates/manage_certs.py unit/test_manage_certs.py

test_unit: venv/unit
	PYTHONPATH=../templates venv/unit/bin/coverage run \
	    --branch --source=../templates -m unittest unit/test_manage_certs.py
	venv/unit/bin/coverage html
	venv/unit/bin/coverage report

test_integration: venv/integration
	@if [ -z "$(TEST_HOSTS)" ]; then \
	    echo "Please set TEST_HOSTS to the inventory file for the test server:"; \
	    echo "    make $@ TEST_hosts=hosts"; \
	    false; \
	fi
	venv/integration/bin/ansible-playbook -vvv -i "$(TEST_HOSTS)" integration/test.yml

update_prospector_config:
	wget -O pylintrc \
	    'https://raw.githubusercontent.com/open-craft/opencraft/master/pylintrc'
	wget -O prospector.yml \
	    'https://raw.githubusercontent.com/open-craft/opencraft/master/.prospector/opencraft.yml'

clean:
	git clean -Xdf

.PHONY: default test test_prospector test_unit test_integration update_prospector_config clean
