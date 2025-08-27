# Regioni
Uvodi se posebna paradigma gde ce se kriticne sekcije oznacavati posebnom sintaksom, takvi kodovski blokovi naznaceni da se izvrsavaju nedeljivo se nazivaju **kriticni regioni**.U javi se ovakvi regioni kreiraju tako sto se ispred bloka naredbi stavi kljucna rec *synchronized*

Kod pristupanja kriticnim regionima implicitno je obezbedjenjo medjusobno **iskljucivanje procesa**, ali sta je sa *uslovnom sinhronizacijom* ?

| Opste        | Java           | 
| ------------- |:-------------| 
| region r do <br>begin<br>&nbsp;&nbsp;critical section<Br>end;| synchronized(reference){<br>&nbsp;&nbsp;critical section<Br>} | 

Sve sto smo u coarse grain resenjima imali izmedju < > generalno se moze staviti u jedan kritican region, te su ovde fine grain resenja trivijalna i necemo se baviti vise prebacivanjem iz coarse i fine grain.

# Uslovni kriticni regioni

*Uslovni* kriticni regioni su regioni koji pored medjusobnog iskljucivanja pruzaju i uslovnu sinhornizaciju, koristeci opcione **await** naredbe. 
Ukoliko se u kodu naislo na await ciji uslov nije zadovoljen, proces se blokira i odrice ekskluzivnog prava pristupa resursu (regionu). Time omogucava da neki drugi proces udje u region i eventualno mozda ispuni uslove na koji cekaju blokirani procesi.

Kada proces *izadje iz u.k.regiona* jedan od blokiranih procesa dobija pravu pristupa i radi sa kriticnom sekcijom. Odabir procesa koji ce se deblokirati je nasumican, te **nema FIFO principa u regionima**. 

| Opste        | Java           | 
| ------------- |:-------------| 
| region r do <br>begin<br>&nbsp;&nbsp;critical section<br>&nbsp;&nbsp;... <br>&nbsp;&nbsp;**await(condition)**<Br>end;| synchronized(reference){<br>&nbsp;&nbsp;...<br>&nbsp;&nbsp;reference.notifyAll()<br>&nbsp;&nbsp;while(!condition)<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;reference.wait()<br>&nbsp;&nbsp;...<br>&nbsp;&nbsp;reference.notifyAll()<Br>} | 

*notify all* ce da probudi sve procese cisto da provere da li se neka promena koja se desila dok su onli blokirani, uticala na njihov condition nije ispunio.

