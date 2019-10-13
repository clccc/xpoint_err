Object.metaClass._getSymbols= { id ->
    symbols = g.v(id).out.has('type','Symbol').id.toList() //.sort()
    return symbols
}

Object.metaClass._getCodeById= { id ->
    code = g.v(id).code //.sort()
    return code
}
