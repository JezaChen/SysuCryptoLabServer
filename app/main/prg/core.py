def tiny_random_generator(seed,
                          p=13835075647472402443,
                          g=12332102632472395673,
                          output_len=512,
                          detailed=False):
    """
    @param detailed 是否输出详细的中间数据
    """
    s_old = seed
    z_str = ""
    z_int = 0
    detailed_output = []
    if detailed:
        detailed_output.append((0, str(seed)))

    for i in range(output_len):
        z_int <<= 1
        si = pow(g, s_old, p)
        s_old = si
        z_str += str(si & 1)
        z_int += (si & 1)
        if detailed:
            detailed_output.append((i + 1, str(si), si & 1))

    return z_str, z_int, detailed_output


if __name__ == '__main__':
    print(tiny_random_generator(20214876, detailed=True))
    # print(binpow(g, seed, p))
