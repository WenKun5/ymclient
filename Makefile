#CC = gcc
YMC_CFLAGS = $(CLAGS) -g -W -Wall -std=gnu99 -fstrict-aliasing -I.
YMC_LIB         = libymc.so
YMC_LIB_LDFLAGS = $(LDFLAGS) -shared -lm -fPIC
YMC_LIB_OBJ     = ymclient.o http.o cJSON.o conf.o commandline.o safe.o debug.o

YMC_CLI         = ymclient
YMC_CLI_LDFLAGS = $(LDFLAGS) -L. -lymc -lm -fPIC
YMC_CLI_OBJ     = ymclient_cli.o

all: $(YMC_LIB) $(YMC_CLI)

%.o: %.c
	$(CC) $(YMC_CFLAGS) -fPIC -c  -o $@ $<

$(YMC_LIB): $(YMC_LIB_OBJ)
	$(CC) $(YMC_LIB_LDFLAGS) -o $(YMC_LIB) $(YMC_LIB_OBJ)


# $(CC) -o $(YMC_CLI) $(YMC_CLI_OBJ) $(YMC_CLI_LDFLAGS)

$(YMC_CLI): $(YMC_CLI_OBJ)
	$(CC) -o $(YMC_CLI) $(YMC_CLI_OBJ) $(YMC_LIB_OBJ) -lm

clean:
	rm -f *.o *.so $(YMC_LIB) $(YMC_CLI)

