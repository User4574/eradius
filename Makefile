Top = eradius
Modules = er_tlv er_packet er_crypto er_aaa er_conv ${Top}
Headers = eradius config

${Top}: $(addsuffix .erl,${Modules})
	erlc $^

.PHONY: run clean edit

run: ${Top}
	erl -s eradius

clean:
	rm -f *.beam erl_crash.dump

edit:
	vim -p $(addsuffix .erl,${Modules}) $(addsuffix .hrl,${Headers})
