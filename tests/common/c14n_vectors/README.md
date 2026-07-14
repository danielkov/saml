# Merlin Exclusive C14N known-answer vector

These fixtures are a reduced, namespace- and whitespace-preserving form of
`tests/merlin-exc-c14n-one/exc-signature.xml` from the xmlsec interoperability
suite at commit `a400a7a714ab26f0cac99c57e008c03f16e2b22f`:

https://github.com/lsh123/xmlsec/tree/a400a7a714ab26f0cac99c57e008c03f16e2b22f/tests/merlin-exc-c14n-one

The original vector was contributed by Merlin Hughes of Baltimore
Technologies. Its four published SHA-1 digest values independently confirm the
four canonical byte streams here: Exclusive C14N with and without comments,
each with and without the inclusive prefix list `bar #default`.

The reduced input removes unrelated `SignedInfo` and key material but preserves
the target `dsig:Object`, its text/comment nodes, and its complete ancestor
namespace context. `LICENSE.xmlsec` carries the license under which the xmlsec
test suite distributes the vector.
