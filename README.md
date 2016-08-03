PSGCK(1)                    General Commands Manual                   PSGCK(1)

NNAAMMEE
     ppssggcckk – check passwd, shadow and group validity

SSYYNNOOPPSSIISS
     ppssggcckk [--vv] [--nn _n_a_m_e_-_r_e_g_e_x] [--pp _p_a_s_s_w_d _f_i_l_e] [--gg _g_r_o_u_p _f_i_l_e]
           [--ss _s_h_a_d_o_w _f_i_l_e]

DDEESSCCRRIIPPTTIIOONN
     ppssggcckk performs verification of the passwd, shadow and group files,
     similar to pwck(8) and grpck(8).  But never changes any of the databases.


OOPPTTIIOONNSS
     --vv      Increase verbosity, and report non-errors. May be given multiple
             times.

     --pp --gg --ss
             Use provided files instead of default files in _/_e_t_c.

     --nn _n_a_m_e_-_r_e_g_e_x
             Use _n_a_m_e_-_r_e_g_e_x to match valid user and group names, instead of
             the default _^_[_a_-_z_]_[_0_-_9_a_-_z_]_*_$.  Be sure to include _^ and _$.


AAUUTTHHOORR
     Written by Lars Lindqvist.

CCOOPPYYRRIIGGHHTT
     Copyright (C) 2016 Lars Lindqvist

LLIICCEENNSSEE
     Permission is hereby granted, free of charge, to any person obtaining a
     copy of this software and associated documentation files (the
     "Software"), to deal in the Software without restriction, including
     without limitation the rights to use, copy, modify, merge, publish,
     distribute, sublicense, and/or sell copies of the Software, and to permit
     persons to whom the Software is furnished to do so, subject to the
     following conditions:

     The above copyright notice and this permission notice shall be included
     in all copies or substantial portions of the Software.

WWAARRRRAANNTTYY
     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
     OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
     MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
     NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
     DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
     OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
     USE OR OTHER DEALINGS IN THE SOFTWARE.


SSEEEE AALLSSEE
     pwck(8), grpck(8).

                                August 3, 2016
