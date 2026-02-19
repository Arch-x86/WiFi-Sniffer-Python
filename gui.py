import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import csv
import os
import logging
from typing import Optional

from sniffer_core import Sniffer, get_interfaces

logger = logging.getLogger(__name__)