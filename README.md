# cryptotool

## Compiling and Running

`mvn package` and `mvn exec:java`

## Add to local maven repo

```
mvn install:install-file \
    -Dfile=target/cryptotool-0.1.jar \
    -DgroupId=net.pdutta.sandbox \
    -DartifactId=cryptotool \
    -Dversion=0.1 \
    -Dpackaging=jar -DcreateChecksum=true
```
