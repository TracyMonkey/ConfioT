# IoTConfiguration




# USAGE

```bash
cd ConfioT/
spin -a IoTConfiguration.pml
gcc -DMEMLIM=16384 -DVECTORSZ=16380 -O2 -DXUSAFE -DSAFETY -DNOCLAIM -DBITSTATE -o pan pan.c
./pan -m1000 -E -e -n > result/result.txt
ls *.trail | xargs -I {} sh -c "spin -k {} -t IoTConfiguration.pml > result/{}.txt"




```
