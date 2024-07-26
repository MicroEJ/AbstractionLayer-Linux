.. 
    Copyright 2024 MicroEJ Corp. All rights reserved.
    Use of this source code is governed by a BSD-style license that can be found with this software.

.. |BOARD_NAME| replace:: i.MX93EVK
.. |VEEPORT| replace:: VEE Port
.. |RTOS| replace:: Linux

.. _README: ./../../../README.rst

================
|BOARD_NAME| BSP
================

This project contains the BSP sources of the |VEEPORT| for the
|BOARD_NAME|. 

This document does not describe how to setup the |VEEPORT|. Please
refer to the `README`_ for that.

Build & Run Scripts
---------------------

In the directory ``Project/microej/scripts/`` are scripts that can be
used to build and flash the BSP.  The ``.bat`` and ``.sh`` scripts are
meant to run in a Windows and Linux environment respectively.

- The ``build*`` scripts are used to compile and link the BSP with a
  MicroEJ Application to produce a MicroEJ Firmware
  (``application.out``) that can be executed on a device.

  The ``build*`` scripts work out of the box, assuming the toolchain is
  installed in the default path.

- The ``run*`` scripts are used to send and execute a MicroEJ Firmware
  (``application.out``) on a device.

The environment variables can be defined globally by the user or in
the ``set_local_env*`` scripts.  When the ``.bat`` (``.sh``) scripts
are executed, the ``set_local_env.bat`` (``set_local_env.sh``) script
is executed if it exists.  Create and configure these files to
customize the environment locally.  Template files are provided as
example, see ``set_local_env.bat.tpl`` and ``set_local_env.sh.tpl``.
