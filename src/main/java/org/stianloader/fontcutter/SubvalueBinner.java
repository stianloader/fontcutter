package org.stianloader.fontcutter;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.function.BiConsumer;
import java.util.function.BinaryOperator;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collector;

import org.jetbrains.annotations.NotNull;

public class SubvalueBinner<@NotNull K, @NotNull T> implements Collector<T, ConcurrentNavigableMap<K, List<T>>, ConcurrentNavigableMap<K, List<T>>> {
    @NotNull
    private final Function<T, K> subvalueComputer;

    public SubvalueBinner(@NotNull Function<T, K> subvalueComputer) {
        this.subvalueComputer = subvalueComputer;
    }

    @Override
    public Supplier<ConcurrentNavigableMap<K, List<T>>> supplier() {
        return ConcurrentSkipListMap::new;
    }

    @Override
    public BiConsumer<ConcurrentNavigableMap<K, List<T>>, T> accumulator() {
        return (map, accumValue) -> {
            map.compute(this.subvalueComputer.apply(accumValue), (_, value) -> {
                if (value == null) {
                    value = new ArrayList<>();
                }
                value.add(accumValue);
                return value;
            });
        };
    }

    @Override
    public BinaryOperator<ConcurrentNavigableMap<K, List<T>>> combiner() {
        return (a, b) -> {
            a.putAll(b);
            return a;
        };
    }

    @Override
    public Function<ConcurrentNavigableMap<K, List<T>>, ConcurrentNavigableMap<K, List<T>>> finisher() {
        return Function.identity();
    }

    @Override
    public Set<Characteristics> characteristics() {
        return Set.of(Characteristics.IDENTITY_FINISH, Characteristics.UNORDERED, Characteristics.CONCURRENT);
    }
}
