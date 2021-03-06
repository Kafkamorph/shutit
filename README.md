<<<<<<< HEAD


[ShutIt](http://shutit.tk)
===============
Complex Docker Deployments Made Simple


REALLY QUICK START
------------------

Videos:
-------

- [Setting up a ShutIt server in 3 minutes](https://www.youtube.com/watch?v=ForTMTUMp3s)

- [Steps for above](https://gist.github.com/ianmiell/947ff3fabc44ace617c6)

- [Configuring and uploading a MySql container](https://www.youtube.com/watch?v=snd2gdsEYTQ)

- [Building a win2048 container](https://www.youtube.com/watch?v=Wagof_wnRRY) cf: [Blog](http://zwischenzugs.wordpress.com/2014/05/09/docker-shutit-and-the-perfect-2048-game/)


Docs:
-----
- [Walkthrough](http://ianmiell.github.io/shutit/)


Do it yourself:
---------------

```
./shutit skeleton --example <new directory> <new module name> <user domain>
```

and follow instructions.


REALLY QUICK OVERVIEW
---------------------
You'll be interested in this if you:

- Want to take your scripts and turn them into stateless containers quickly,
without needing to learn or maintain a configuration management solution.

- Are a programmer who wants highly configurable containers for
differing use cases and environments.

- Find dockerfiles a great idea, but limiting in practice.

- Want to build stateless containers for production.

- Are interested in "phoenix deployment" using Docker.

I WANT TO SEE EXAMPLES
----------------------
See in ```library/*```
eg
```
cd library/mysql
./build.sh
./run.sh
```

Overview
--------
While evaluating Docker for my corp (openbet.com) I reached a point where
using Dockerfiles was somewhat painful or verbose for complex and/or long and/or
configurable interactions. So we wrote our own for our purposes.

ShutIt works in the following way:

- It runs a docker container (base image configurable)
- Within this container it runs through configurable set of modules (each with
  a globally unique module id) that runs in a defined order with a standard
  lifecycle:
     - dependency checking
     - conflict checking
     - remove configured modules
     - build configured modules
     - tag (and optionally push) configured modules (to return to that point
       of the build if desired)
     - test
     - finalize module ready for closure (ie not going to start/stop anything)
     - tag (and optionally push) finished container
- These modules must implement an abstract base class that forces the user to
  follow a lifecycle (like many test frameworks)
- It's written in python
- It's got a bunch of utility functions already written, eg:
     - pause_point (stop during build and give shell until you decide to 
       return to the script (v useful for debugging))
     - add_line_to_file (if line is not already there)
     - add_to_bashrc (to add something to everyone's login)
     - setup_prompt (to handle shell prompt oddities in a 
       reliable/predictable way)
     - is user_id_available
     - set_password (package-management aware)
     - file_exists
     - get_file_perms
     - package_installed (determine whether package is already installed)
     - loads more to come

If you have an existing bash script it is relatively trivial to port to this 
to get going with docker and start shipping containers (see create\_skeleton.sh
below).

As a by-product of this design, you can use it in a similar way to chef/puppet
(by taking an existing container and configuring it to remove and build a
specific module), but it's not designed for this purpose and probably won't 
be as useful for moving target systems.

Chef/Puppet were suggested as alternatives, but for several reasons I didn't go
with them:

- I had to deliver something useful, and fast (spare time evaluation), so 
  taking time out to learn chef was not an option
- It struck me that what I was trying to do was the opposite of what chef is
  trying to do, ie I'm building static containers for a homogeneous environment
  rather than defining state for a heterogeneous machine estate and hoping
  it'll all work out
- I was very familiar with (p)expect, which was a good fit for this job and
  relatively easy to debug
- Anecdotally I'd heard that chef debugging was painful ("It works 100% of the
  time 60% of the time")
- I figured we could move quite easily to whatever CM tool was considered
  appropriate once we had a deterministic set of steps that also documented
  server requirements



It is designed to:

- create static containers in as deterministic and predictable way as
  manageable
- handle complex inputs and outputs
- easy to learn
- easy to convert existing shell scripts
- have (limited) functionality for rebuilding specific modules

If you are a sysadmin looking for something to manage dynamic, moving target
systems stick with chef/puppet. If you're a programmer who wants to manage a
bunch of existing scripts in a painless way, keep on reading.

Directory Structure
--------
Each module directory should contain modules that are grouped together somehow
and all/most often built as an atomic unit.
This grouping is left to the user to decide, but generally speaking a module
will have one relatively simple .py file.

Each module .py file should represent a single unit of build. Again, this unit's
scope is for the user to decide, but it's best that each module doesn't get too
large.

Within each module directory the following directories are placed as part of
`./shutit skeleton`.

- test
    - should contain ```test_`hostname`.sh``` executables which exit with a 
            code of 0 if all is ok.
- resources
    - mount point for container during build. Files too big to be part of
         source control can be  or read from here. Can be controlled through
         cnf files ([host]/resources_dir:directory)
         - it's suggested you set this in
             ```/path/to/shutit/configs/`hostname`_`username`.cnf``` to 
             ```/path/to/shutit/resources```.
- configs
    - default configuration files are placed here.

These config files are also created, defaulted, and automatically sourced:

```
configs/build.cnf                  - 
```

And these files are also automatically created:

```
configs/README.md                  - README for filling out if required
resources/README.md                - README for filling out if required
run.sh                             - Script to run modules built with build.sh
build.sh                           - Script to build the module
```

Configuration
--------
See config files (in configs dirs) for guidance on setting config.

Tests
--------
Run 

```
./test.sh
```

Dependencies
--------------
- python 2.7+
- See [here](https://gist.github.com/ianmiell/947ff3fabc44ace617c6) for a minimal build.



Known Issues
--------------
Since a core technology used in this application is pexpect - and a typical
usage pattern is to expect the prompt to return - unusual shell
prompts and escape sequences have been known to cause problems.
Use the ```shutit.setup_prompt()``` function to help manage this by setting up
a more sane prompt.
Use of ```COMMAND_PROMPT``` with ```echo -ne``` has been seen to cause problems
with overwriting of shells and pexpect patterns.

=======
[ShutIt](http://shutit.tk)
==========================


[![Join the chat at https://gitter.im/ianmiell/shutit](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/ianmiell/shutit?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

A versatile automation framework.

ShutIt is an automation tool that models a user's actions on a terminal.

It can automate any process that can be run by a human on the command line with little effort.

It was originally written to manage complex Docker builds, but is a now general-purpose automation tool that supports bash, Docker, Vagrant, ssh and arbitrary build contexts.

If you want to know more about Docker, see the [official site](https://www.docker.com/) or take a look at the book by the creators of ShutIt - [Docker in Practice](http://docker-in-practice.github.io/).

ShutIt is also an educational tool, as it can produce videos of demos, capture reproducible steps required to set environments up, and even challenge you to get the right output (see [grep-scales](https://github.com/ianmiell/grep-scales)).

Really Quick Overview
=====================
Some use cases:

- You like bash, want to automate tasks, have structure and support, but don't want to learn a configuration management framework that takes you away from the command line you know and love.

- Are a programmer who wants highly configurable stateless containers development, testing, and production.

- Want to [build everything from source](https://github.com/ianmiell/shutit-distro/blob/master/README.md) in a way that's comprehensible and auditable.

- Want to create instructive [walkthroughs](https://asciinema.org/a/30598?t=70): 

- Want to take your scripts and turn them into stateless containers quickly, without needing to maintain (or learn) a configuration management solution designed for moving-target systems.

- Are interested in "phoenix deployment".


What Does it Do (bash Builds)?
==============================

ShutIt acts as a modular and easy to use wrapper around [pexpect](https://github.com/pexpect/pexpect).

Here is a simple example of a script that creates file if they are not there already:

[![Simple Example](https://asciinema.org/a/47076.png)](https://asciinema.org/a/47076)

What Does it Do (Tutorials)?
============================

This builds on the docker features (see below), but allows you to interrupt the run at points of your choosing with 'challenges' for the user to overcome.

Two types of 'challenge' exist in ShutIt:

- scales
- free form

Scales tell you to run a specific command before continuing. This is useful when you want to get certain commands or flags 'under your fingers', which does not happen without dedicated and direct practice.

[![grep Scales](https://asciinema.org/a/41308.png)](https://asciinema.org/a/41308)

Free form exercises give you a task to perform, and free access to the shell. This is to give the user a realistic environment in which to hone their skills. You can check man pages, look around the directories, search for useful utils (even install new ones!). When you are finished, a pre-specified command is run to check the system is in an appropriate state. Here's an example for the [basics of git](ianmiell.github.io/git-101-tutorial/):

[![git 101 Tutorial](https://asciinema.org/a/44937.png)](https://asciinema.org/a/44937)

If you use a Docker-based tutorial and you mess the environment up, the state can be restored to a known one by hitting CTRL-G.



What Does it Do (Vagrant)?
==========================
Uses a bash build to set up a vagrant machine. This allows another kind of contained environment for more infrastructural projects than Docker allows for.

This example demonstrates a reproducible build that sets up Docker on an Ubuntu VM (on a Linux host), then runs a CentOS image within Docker wihing the Ubuntu VM.

It deposits the user into a shell mid-build to interrogate the environment, after which the user re-runs the build to add a directive to ensure ps is installed in the image.

[![Docker on Ubuntu VM running a CentOS image](https://asciinema.org/a/47078.png)](https://asciinema.org/a/47078)

There is a multinode option for Vagrant multinode projects.


What Does it Do (Docker Builds)?
================================

![Example Setup]
(https://github.com/ianmiell/shutit/blob/gh-pages/images/ShutIt.png)

We start with a "ShutIt Module", similar to a shell script, or a Dockerfile (see bash builds above).

In the image above there are five of these. At a high level they each have the following attributes:

- a list of zero or more dependencies on other modules
- a unique number that represents its ordering within the available modules
- a set of steps (bash commands) for building the module

In the image we imagine a scenario where we want to build our blog into a docker image, with all its attendant content and config.

We instruct ShutIt to build the MyBlog module, and it runs the build as per the image on the right.

The container environment is set up, the modules are ordered, and the build steps are run. Finally, the image is committed, tagged and pushed as configured.

This is a core function of ShutIt - to manage dependencies and image building for complex image setups.

But it doesn't just run build steps, it also manages The ShutIt Lifecycle to make the build more robust and flexible.


The ShutIt Lifecycle
====================

- gathers all the modules it can find in its path and determines their ordering
- for all modules, it gathers any build-specific config (e.g. passwords etc.)
- it checks dependencies and conflicts across all modules and figures out which modules need to be built
- for all modules, it checks whether the module is already installed
- for all modules, if it needs building, it runs the build
- for all modules, run a test cycle to ensure everything is as we expect
- for all modules, run a finalize function to clean up the container
- do any configured committing, tagging and pushing of the image

These correspond to the various functions that can be implemented in the ShutIt module file.


Auto-Generate Modules
=====================

ShutIt provides a means for auto-generation of modules (either bare ones, or from existing Dockerfiles) with its skeleton command. See [here](http://ianmiell.github.io/shutit/) for an example.


[Really Quick Start](http://ianmiell.github.io/shutit)
====================

[Full User Guide](http://github.com/ianmiell/shutit-docs/blob/master/USER_GUIDE.md)
==============

[API](http://github.com/ianmiell/shutit-docs/blob/master/API.md)
======

[Installation](http://github.com/ianmiell/shutit-docs/blob/master/INSTALL.md)
==============

Contributing
============

We always need help, and with a potentially infinite number of libraries required, it's likely you will be able to contribute. Just mail ian.miell@gmail.com if you want to be assigned a mentor. [He won't bite](https://www.youtube.com/watch?v=zVUPmmUU3yY) 

[Tests](http://github.com/ianmiell/shutit/blob/master/docs/TEST.md)

Mailing List
------------
https://groups.google.com/forum/#!forum/shutit-users
shutit-users@groups.google.com

Known Issues
=============
Since a core technology used in this application is pexpect - and a typical usage pattern is to expect the prompt to return.
Unusual shell prompts and escape sequences have been known to cause problems. Use the shutit.setup_prompt() function to help manage this by setting up a more sane prompt.
Use of COMMAND_PROMPT with echo -ne has been seen to cause problems with overwriting of shells and pexpect patterns.


[![ScreenShot](https://raw.github.com/GabLeRoux/WebMole/master/ressources/WebMole_Youtube_Video.png)](https://www.youtube.com/watch?v=gsEtaX207a4)
>>>>>>> upstream/master

Licence
------------
The MIT License (MIT)

Copyright (C) 2014 OpenBet Limited

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in 
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

