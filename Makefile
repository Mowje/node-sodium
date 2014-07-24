SHELL := /bin/bash
TESTS = test/*.js
REPORTER = dot

CHDIR_SHELL := $(SHELL)
define chdir
   $(eval _D=$(firstword $(1) $(@D)))
   $(info $(MAKE): cd $(_D)) $(eval SHELL = cd $(_D); $(CHDIR_SHELL))
endef

test:
	@echo Run make test-cov for coverage reports
	@echo Mocha and Instanbul Node.js must be installed globally
	@NODE_ENV=test mocha \
		-R $(REPORTER) \
		$(TESTS)

instrument: clean
	istanbul instrument --output lib-cov --no-compact --variable global.__coverage__ lib


test-cov: clean instrument
	@echo Run make test for simple tests with no coverage reports
	@echo Mocha and Istanbul Node.js must be installed globally
	@COVERAGE=1 NODE_ENV=test mocha \
		-R mocha-istanbul \
		$(TESTS)
	@istanbul report
	@rm -rf lib-cov
	@echo
	@echo Open html-report/index.html file in your browser

git-pull:
	git pull
	git submodule init
	git submodule update
	git submodule status

git-getsodium:
	rm -rf libsodium
	git init
	git submodule add https://github.com/jedisct1/libsodium.git
	git submodule update
	cd libsodium; \
	git reset --hard dc1e4b468dfb18cb69ab284cbc362288a1ce8df1; \
	git checkout -f dc1e4b468dfb18cb69ab284cbc362288a1ce8df1

clean:
	-rm -fr lib-cov
	-rm -fr covershot
	-rm -fr html-report
	-rm -fr coverage
	-rm -fr coverage.html

sodium:
	cd libsodium && \
	./autogen.sh && \
    ./configure && \
	make && make check
	node-gyp rebuild

.PHONY: test-cov site docs test docclean
