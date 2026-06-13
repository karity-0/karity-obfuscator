function fibo(n)
    if n <= 1 then
        return n
    end

    return fibo(n - 1) + fibo(n - 2)
end

print(fibo(10)) -- 55