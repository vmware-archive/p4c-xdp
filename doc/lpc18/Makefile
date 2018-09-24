TEXFILES = background.tex compilation.tex conclusions.tex introduction.tex results.tex testing.tex top.tex
FIGURES =
GRAPHS =

top.pdf: $(FIGURES) $(TEXFILES) $(GRAPHS)
	texi2pdf top.tex -o p4cxdp-lpc18.pdf
	xdg-open p4cxdp-lpc18.pdf

clean: clean-graphs clean-figures
	rm -f top.bbl top.blg top.log top.aux
	rm -f p4cxdp-lpc18.pdf

clean-graphs:
	rm -f $(GRAPHS)

clean-figures:
	rm -f $(FIGURES)

%.pdf: %.eps
	epstopdf $< > $@
