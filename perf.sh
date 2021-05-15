perf record -F 99 -p 9725 -g -- sleep 6000

采样完成执行下面命令，生成火焰图
perf script > out.perf
/home/sunyy/xl/FlameGraph/stackcollapse-perf.pl out.perf > out.folded
/home/sunyy/xl/FlameGraph/flamegraph.pl out.folded > out.svg
