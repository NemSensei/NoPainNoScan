"""npns_common.py — plomberie partagée des scripts NoPainNoScan.

Centralise ce qui était dupliqué à l'identique dans chaque check_*.py et dans le
script de découverte : couleurs ANSI (désactivées hors terminal / NO_COLOR), les
helpers log_*, la vérification de présence d'outil, et la confirmation d'étape
interactive avec sa progression.

Chaque script importe ce dont il a besoin, p.ex. :
    from npns_common import (C, RULE, log_info, log_ok, log_warn, log_err, log_step,
                             tool_exists, confirm_step, set_total_steps,
                             enable_auto_accept, emit_progress)

Le module vit à côté des scripts : il s'importe sans configuration de PYTHONPATH
(Python place le dossier du script lancé en tête de sys.path).

NB : `run()` (wrapper subprocess) et le parsing des cibles restent propres à
chaque script (timeouts par défaut et logique de parsing qui diffèrent).
"""

from __future__ import annotations

import os
import shutil
import sys

# Progression pour l'UI web ; no-op si le helper est absent (exécution standalone).
try:
    from _npns_progress import emit_progress
except Exception:
    def emit_progress(*a, **k):
        pass


# =============================================================================
# COULEURS
# =============================================================================
class C:
    HEADER = '\033[95m'
    BLUE   = '\033[94m'
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    WARN   = '\033[93m'
    FAIL   = '\033[91m'
    DIM    = '\033[2m'
    ENDC   = '\033[0m'
    BOLD   = '\033[1m'


# Couleurs seulement sur un terminal interactif ; désactivées si piped (UI web) ou NO_COLOR.
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    for _k in list(vars(C)):
        if _k.isupper():
            setattr(C, _k, "")

RULE = "-" * 60


# =============================================================================
# LOGGING — tags alignés, colorés (Style C)
# =============================================================================
def log_info(msg): print(f"{C.CYAN}[INFO]{C.ENDC} {msg}")
def log_ok(msg):   print(f"{C.GREEN}[ OK ]{C.ENDC} {msg}")
def log_warn(msg): print(f"{C.WARN}[WARN]{C.ENDC} {msg}")
def log_err(msg):  print(f"{C.FAIL}[FAIL]{C.ENDC} {msg}")
def log_step(msg): print(f"\n{C.BOLD}==> {msg}{C.ENDC}\n{C.DIM}{RULE}{C.ENDC}")


# =============================================================================
# OUTILS
# =============================================================================
def tool_exists(name):
    return shutil.which(name) is not None


# =============================================================================
# CONFIRMATION D'ÉTAPE + PROGRESSION
# =============================================================================
_AUTO_ACCEPT = False
_STEP_SEEN = 0
_TOTAL_STEPS = 0


def set_total_steps(n):
    """Déclare le nombre total d'étapes du script (pour le % de progression)."""
    global _TOTAL_STEPS
    _TOTAL_STEPS = int(n)


def enable_auto_accept():
    """Mode non-interactif (--yes) : accepte toutes les étapes sans prompt."""
    global _AUTO_ACCEPT
    _AUTO_ACCEPT = True


def confirm_step(step_name, detail=None):
    """Valide une étape avant de lancer ses commandes ; émet la progression.

    Retourne True si l'étape doit s'exécuter. En mode auto-accept (--yes), ne
    pose pas de question. Chaque étape acceptée incrémente le compteur de
    progression consommé par l'UI web.
    """
    global _AUTO_ACCEPT, _STEP_SEEN
    proceed = _AUTO_ACCEPT
    if not proceed:
        print(f"\n{C.WARN}[?]{C.ENDC} {C.BOLD}{step_name}{C.ENDC} is about to run.")
        if detail:
            print(f"    {C.CYAN}{detail}{C.ENDC}")
        resp = input("    Proceed? [y/N/a=accept all remaining] ").strip().lower()
        if resp in ("a", "all"):
            _AUTO_ACCEPT = True
            proceed = True
        elif resp in ("y", "yes"):
            proceed = True
    if proceed:
        _STEP_SEEN += 1
        emit_progress(_STEP_SEEN, _TOTAL_STEPS, label=step_name)
        return True
    log_warn(f"Skipped by user: {step_name}")
    return False


def sub_progress(host, hosts, label=None):
    """Sous-progression PAR HÔTE à l'intérieur de l'étape courante.

    Pour les scripts qui bouclent en Python sur les hôtes (ex. ssh) : affine la
    barre entre deux étapes. Utilise l'étape et le total courants du module.
    """
    emit_progress(_STEP_SEEN, _TOTAL_STEPS, label=label, host=host, hosts=hosts)
