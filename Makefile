Modules = er_tlv er_packet er_auth er_conv eradius

all: $(addsuffix .beam,${Modules})

%.beam: %.erl
	erlc $^

.PHONY: run clean edit

run: $(addsuffix .beam,${Modules})
	erl -s eradius

clean:
	rm -f *.beam erl_crash.dump

edit:
	vim -p *.erl *.hrl
