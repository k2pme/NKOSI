rule eicar_test {
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    condition:
        $eicar
}
