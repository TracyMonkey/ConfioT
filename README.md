# IoTConfiguration

Currently, we only provide the the demo model for devices for verification purpose and we will responsibly update all complete models after obtaining consent from the vendors involved.


# USAGE

```bash
cd ConfioT/
spin -a IoTConfiguration.pml
gcc -DMEMLIM=16384 -DVECTORSZ=16380 -O2 -DXUSAFE -DSAFETY -DNOCLAIM -DBITSTATE -o pan pan.c
./pan -m2000 -E -e -n > result/result.txt
ls *.trail | xargs -I {} sh -c "spin -k {} -t IoTConfiguration.pml > result/{}.txt"
```


# Questionnaire

See `./Questionnaire.pdf`.
