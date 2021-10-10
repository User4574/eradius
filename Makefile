Modules = er_tlv er_packet er_crypto er_aaa er_flow er_test er_conv eradius
Headers = eradius config

.PHONY: run clean edit test

$(addsuffix .beam,${Modules}): $(addsuffix .erl,${Modules})
	erlc $^

run: $(addsuffix .beam,${Modules})
	erl -s eradius

clean:
	rm -f *.beam erl_crash.dump

edit:
	vim -p $(addsuffix .erl,${Modules}) $(addsuffix .hrl,${Headers}) Makefile

test:
	./2865test.sh
