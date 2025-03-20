#! /bin/sh
./otp -rTEST -n4 -mt1.md5 >test.out
./otp -rTEST -n3 -c12 -mt2.md5 >>test.out
./otp -rTEST -n3 -e12 -mt3.md5 >>test.out
./otp -rTEST -n4 -S5 -e -c -mt4.md5 >>test.out
./otp -rTEST -n7 -d4 -mt5.md5 >>test.out
cat t1.md5 >>test.out
cat t2.md5 >>test.out
cat t3.md5 >>test.out
cat t4.md5 >>test.out
cat t5.md5 >>test.out
