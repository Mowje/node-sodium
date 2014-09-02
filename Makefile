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
	git clone https://github.com/jedisct1/libsodium.git libsodium; \
	cd libsodium; \
	git reset --hard dc1e4b468dfb18cb69ab284cbc362288a1ce8df1; \
	git checkout -f dc1e4b468dfb18cb69ab284cbc362288a1ce8df1

clean:
	-rm -fr lib-cov
	-rm -fr covershot
	-rm -fr html-report
	-rm -fr coverage
	-rm -fr coverage.html
	-rm -rf build/nw
	#-rm -rf build/buildbase
	-rm -rf test-nw/node_modules

sodium:
	cd libsodium && \
	./autogen.sh && \
	./configure && \
	make && make check
	node-gyp rebuild

sodium-nw:
	nw-gyp rebuild --target=0.8.4

get-buildbase-osx:
	if [ -d "./build/buildbase/osx/node-webkit.app" ]; \
	then \
		echo "Found node-webkit.app\n"; \
	else \
		mkdir -p build/buildbase/; \
		wget http://dl.node-webkit.org/v0.8.6/node-webkit-v0.8.6-osx-ia32.zip -O build/buildbase/node-webkit-osx.zip; \
		cd build/buildbase && \
		mkdir osx && \
		unzip node-webkit-osx.zip -d osx; \
	fi ; \

package-nw:
	cd test-nw && zip -r ../build/nw/app.nw *
	if [ -d "./build/nw/test-nw.app" ]; \
	then \
		rm -r build/nw/test-nw.app; \
	fi; \
	cd build/nw && cp -r ../buildbase/osx/node-webkit.app test-nw.app && \
	cp app.nw test-nw.app/Contents/Resources/app.nw

build-test-nw-osx: clean get-buildbase-osx
	mkdir -p build/nw
	mkdir -p test-nw/node_modules
	cd test-nw/node_modules && git clone https://github.com/Mowje/node-sodium.git sodium && \
	cd sodium && npm install should && git clone https://github.com/jedisct1/libsodium.git -b 0.6.1 libsodium && cd libsodium && \
	export CFLAGS="-arch i386" && \
	./autogen.sh && ./configure && make && cd .. && \
	nw-gyp rebuild --target=0.8.6 --arch=i386
	make package-nw
	

.PHONY: test-cov site docs test docclean
