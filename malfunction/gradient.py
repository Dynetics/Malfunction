# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------
# gradient.py
#
# Authors: James Brahm, Matthew Rogers, Morgan Wagner, Jeramy Lochner,
# Donte Brock
# -----------------------------------------------------------------------
# Copyright 2015 Dynetics, Inc.
#
# This file is a part of Malfunction
#
# Malfunction is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Malfunction is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------

import os


def print_underscores(colors, color_amount, padding=0):
    """ Prints the underscores for the unfilled side of the gradient """

    for color in colors:
        if padding:
            print((("\033[38;5;"+str(color)+"m"
                    +"_\033[0m")*(color_amount-1)), end="")
            padding -= 1
        else:
            print((("\033[38;5;"+str(color)+"m"
                    +"_\033[0m")*color_amount), end="")


def gradient(score):
    """ Creates a -100 - 100 gradient based on a given score
    between -100,100 in a terminal """

    score = int(score)
    if score > 100 or score < -100:
        print("Not a valid score")
        return -1

    left_colors = [160, 196, 202, 214, 220]
    middle_color = 226
    right_colors = [190, 154, 118, 82, 46]

    rows, columns = os.popen("stty size", "r").read().split()
    columns = int(columns) - 1
    color_amount = int((columns-1)/10)
    color_index = 0

    padding = len(str(score)) - 1
    buf = (((columns % 10) - len(str(score)))+1)/2
    print((" "*(int(buf/2))), end="")

    if score > 0:
        print_underscores(left_colors, color_amount, padding)
        print("\033[48;5;"+str(middle_color)+"m"+str(score)+"\033[0m", end="")
        for i in range(color_amount*5):
            if i % color_amount == 0 and i > 0 and color_index < 4:
                color_index += 1
            if i < ((score/100.0)*color_amount*5):
                print("\033[48;5;"+str(right_colors[color_index])+"m"
                      +"_\033[0m", end="")
            else:
                print("\033[38;5;"+str(right_colors[color_index])+"m"
                      +"_\033[0m", end="")
    elif score == 0:
        print_underscores(left_colors, color_amount)
        print("\033[48;5;"+str(middle_color)+"m"+str(score)+"\033[0m", end="")
        print_underscores(right_colors, color_amount)
    else:
        score = score*-1
        for i in range(color_amount*5):
            if i % color_amount == 0 and i > 0 and color_index < 4:
                color_index += 1
            if i >= (((100-score)/100.0)*color_amount*5):
                print("\033[48;5;"+str(left_colors[color_index])+"m"
                      +"_\033[0m", end="")
            else:
                print("\033[38;5;"+str(left_colors[color_index])+"m"
                      +"_\033[0m", end="")
        print("\033[48;5;"+str(middle_color)+"m"+str(-score)+"\033[0m", end="")
        print_underscores(right_colors, color_amount, padding)
    print("\n")
