PSGCK(1)                    General Commands Manual                   PSGCK(1)

NNAME
     ppsgck - check passwd, shadow and group validity

SSYNOPSIS
     ppsgck [-v] [-n name-regex] [-p passwd file] [-g group file]
           [--s shadow file]

DDESCRIPTION
     ppsgck performs verification of the passwd, shadow and group files,
     similar to pwck(8) and grpck(8).  But never changes any of the databases.


OOPTIONS
     --v      Increase verbosity, and report non-errors. May be given multiple
             times.

     --p -g -s
             Use provided files instead of default files in _/etc.

     --n name-regex
             Use _name-regex to match valid user and group names, instead of
             the default _^[a-z][0-9a-z]*$.  Be sure to include ^ and $.


AAUTHOR
     Written by Lars Lindqvist.

CCOPYRIGHT
     Copyright (C) 2016 Lars Lindqvist

LLICENSE
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the
     "Software"), to deal in the Software without restriction, including
     without limitation the rights to use, copy, modify, merge, publish,
     distribute, sublicense, and/or sell copies of the Software, and to permit
     persons to whom the Software is furnished to do so, subject to the
     following conditions:

     The above copyright notice and this permission notice shall be included
     in all copies or substantial portions of the Software.

WWARRANTY
     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
     OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
     NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
     DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
     OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
     USE OR OTHER DEALINGS IN THE SOFTWARE.


SSEE ALSE
     pwck(8), grpck(8).

                                August 3, 2016
