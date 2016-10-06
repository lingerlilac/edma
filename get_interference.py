import math
from scipy import integrate


def integration(ft, fr, wt, wr):

    # def fun(x, w, f):
    #     if abs(x - f) >= 1.5 * w:
    #         return 0.0001
    #     elif abs(x - f) >= w and abs(x - f) < 1.5 * w:
    #         return 0.00158489319246111348520210137339
    #     elif abs(x - f) >= 0.55 * w and abs(x - f) < w:
    #         return 0.001
    #     else:
    #         return 1.0
    def fun(x, w, f):
        if abs(x - f) >= 1.1 * w:
            return 0.00001
        elif abs(x - f) >= 0.55 * w and abs(x - f) < 1.1 * w:
            return 0.001
        else:
            return 1.0

    def function(x):
        return fun(x, wr, fr) * fun(x, wt, ft)

    def function1(x):
        return fun(x, wt, ft)
    result1, err1 = integrate.quad(function, -60, 60)
    result2, err2 = integrate.quad(function1, -60, 60)
    result = result1 / result2
    return result, result1, result2


print integration(0, 0, 20, 20)
