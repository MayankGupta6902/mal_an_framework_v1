"""
BatchFileProcessor.py

A utility for deobfuscating batch files by extracting and resolving variables.
Part of the HashParseSuite integrated into Windows Malware Analysis Framework.

Classes:
    BatchFileProcessor: Process batch files and deobfuscate variable references

Author: Mayank Gupta
Date: 2025
"""
import re
import logging
from typing import Dict, List, Optional, Set

# Configure logger
logger = logging.getLogger(__name__)

class BatchFileProcessor:
    """
    A class for processing and deobfuscating batch files.
    
    Extracts variables from SET statements and resolves variable references
    to deobfuscate commands.
    """
    
    # Regular expression patterns
    SET_PATTERN = re.compile(r"set\s+(\w+)\s*=\s*(.*)", re.IGNORECASE)
    VAR_PATTERN = re.compile(r"%(\w+)%")

    def __init__(self, content=None):
        """
        Initialize the batch file processor.
        
        Args:
            content (str, optional): Batch file content to process
        """
        self.content = content
        self.variables = {}
        self.undefined_vars = set()
        
        if content:
            self.variables = self.parse_set_lines(content.splitlines())
            logger.info(f"Initialized BatchFileProcessor with {len(self.variables)} variables")

    def parse_set_lines(self, lines: List[str]) -> Dict[str, str]:
        """
        Parse SET statements from batch file lines.
        
        Args:
            lines (List[str]): Lines of batch file content
            
        Returns:
            Dict[str, str]: Dictionary of variable names and values
        """
        var_dict = {}
        for line in lines:
            line = line.strip()
            if line.lower().startswith("set "):
                match = self.SET_PATTERN.match(line)
                if match:
                    key, value = match.groups()
                    key = key.strip()
                    # Assign space if value is empty or whitespace only
                    if value.strip() == "":
                        value = " "
                    else:
                        # Remove optional quotes around the value
                        value = value.strip().strip('"')
                    var_dict[key] = value
                    logger.debug(f"Captured SET variable: {key} = '{value}'")
                else:
                    logger.warning(f"Malformed SET line: {line}")
                    
        logger.info(f"Extracted {len(var_dict)} variables from batch file")
        return var_dict

    def get_variables(self) -> Dict[str, str]:
        """
        Get the dictionary of variables extracted from the batch file.
        
        Returns:
            Dict[str, str]: Dictionary of variable names and values
        """
        return self.variables

    def extract_variable_lines(self, lines: List[str]) -> List[str]:
        """
        Extract lines containing variable references.
        
        Args:
            lines (List[str]): Lines of batch file content
            
        Returns:
            List[str]: Lines containing variable references
        """
        var_lines = []
        for line in lines:
            if self.VAR_PATTERN.search(line):
                logger.debug(f"Found variable usage: {line.strip()}")
                var_lines.append(line.strip())
                
        logger.info(f"Found {len(var_lines)} lines with variable references")
        return var_lines

    def deobfuscate_line(self, line: str, var_dict: Dict[str, str], undefined_vars: Set[str]) -> str:
        """
        Deobfuscate a single line by resolving variable references.
        
        Args:
            line (str): Line to deobfuscate
            var_dict (Dict[str, str]): Dictionary of variable names and values
            undefined_vars (Set[str]): Set to track undefined variables
            
        Returns:
            str: Deobfuscated line with variables replaced by their values
        """
        def replace_var(match):
            var_name = match.group(1)
            if var_name in var_dict:
                value = var_dict[var_name]
                logger.debug(f"Replacing %{var_name}% with '{value}'")
                return value
            else:
                logger.warning(f"Variable %{var_name}% not defined.")
                undefined_vars.add(var_name)
                return match.group(0)  # Leave unchanged if undefined

        previous = None
        result = line
        # Repeatedly replace variables until no more changes
        while result != previous:
            previous = result
            result = self.VAR_PATTERN.sub(replace_var, result)
            
        logger.debug(f"Deobfuscated: {line} -> {result}")
        return result

    def deobfuscate(self, keep_comments=False) -> str:
        """
        Deobfuscate all variable references in the batch file content.
        
        Args:
            keep_comments (bool, optional): Whether to keep comment lines (REM)
                in the output. Default is False.
                
        Returns:
            str: Deobfuscated batch file content
        """
        if not self.content:
            logger.warning("No content to deobfuscate")
            return ""
            
        lines = self.content.splitlines()
        
        # Decide what lines to process based on keep_comments
        if keep_comments:
            # Get all lines with variables and REM lines
            var_lines = self.extract_variable_lines(lines)
            rem_lines = [line for line in lines if line.strip().lower().startswith("rem ")]
            lines_to_process = var_lines + rem_lines
        else:
            # Just get variable lines
            var_lines = self.extract_variable_lines(lines)
            lines_to_process = var_lines
        
        if not lines_to_process:
            logger.warning("No variable usages or comments found to deobfuscate")
            return self.content
            
        # Reset undefined variables set
        self.undefined_vars = set()
        
        # Deobfuscate each line
        deobfuscated_lines = []
        for line in lines_to_process:
            if line.strip().lower().startswith("rem ") and keep_comments:
                # Keep comment lines as is
                deobfuscated_lines.append(line)
            else:
                # Deobfuscate variable lines
                deobfuscated_lines.append(self.deobfuscate_line(line, self.variables, self.undefined_vars))
        
        logger.info(f"Deobfuscated {len(deobfuscated_lines)} lines, found {len(self.undefined_vars)} undefined variables")
        return "\n".join(deobfuscated_lines)
        
    def deobfuscate_full_script(self, keep_comments=False) -> str:
        """
        Deobfuscate the entire batch file.

        - Keeps only lines with variable references (e.g., %VAR%) by default.
        - Removes all SET variable declarations.
        - Optionally keeps all other lines (comments, REM lines, gibberish) if keep_comments=True.

        Args:
            keep_comments (bool, optional): If True, non-obfuscated lines are kept as comments.
            
        Returns:
            str: Deobfuscated script.
        """
        if not self.content:
            logger.warning("No content to deobfuscate")
            return ""
            
        lines = self.content.splitlines()
        result_lines = []

        # Reset undefined variables set
        self.undefined_vars = set()

        for line in lines:
            stripped_line = line.strip()

            # Skip empty lines
            if not stripped_line:
                continue

            # Skip SET variable declarations
            if self.SET_PATTERN.match(stripped_line):
                logger.debug(f"Skipping SET declaration: {stripped_line}")
                continue

            # Keep and deobfuscate lines containing variable references
            if self.VAR_PATTERN.search(line):
                deobfuscated = self.deobfuscate_line(line, self.variables, self.undefined_vars)
                result_lines.append(deobfuscated)
                logger.debug(f"Deobfuscated line: {stripped_line} -> {deobfuscated}")
            else:
                if keep_comments:
                    result_lines.append(line)
                    logger.debug(f"Preserving comment-like line: {stripped_line}")
                else:
                    logger.debug(f"Skipping comment-like line: {stripped_line}")

        logger.info(f"Deobfuscation complete: {len(result_lines)} lines kept, {len(self.undefined_vars)} undefined variables")
        return "\n".join(result_lines)


    def get_undefined_variables(self) -> List[str]:
        """
        Get list of undefined variables referenced in the batch file.
        
        Returns:
            List[str]: List of undefined variable names
        """
        return sorted(list(self.undefined_vars))

def main():
    """
    Example usage of the BatchFileProcessor class.
    """
    # Example batch script content
    batch_content = """
    @echo off
    REM Setting variables 
    set var1= 
    set var2=Hello
    set var3="World"
    REM Using variables
    echo Start%var1%End
    echo %var2% %var3%
    echo %undefinedVar%
    echo This line has no variables
    REM Nested usage (simulate)
    set nested1=%var2% %var3%
    echo Nested: %nested1%
    """

    # Initialize the processor with the batch content
    processor = BatchFileProcessor(batch_content)
    
    # Get variables and deobfuscated content
    variables = processor.get_variables()
    deobfuscated = processor.deobfuscate(keep_comments=True)
    full_deobfuscated_no_comments = processor.deobfuscate_full_script(keep_comments=False)
    full_deobfuscated_with_comments = processor.deobfuscate_full_script(keep_comments=True)
    undefined_vars = processor.get_undefined_variables()
    
    # Display results
    print("=== Extracted Dictionary ===")
    for k, v in variables.items():
        print(f"{k} = '{v}'")

    print("\n=== Original Content with Variables ===")
    print(batch_content)

    print("\n=== Deobfuscated Variable Lines Only ===")
    print(deobfuscated)
    
    print("\n=== Deobfuscated Full Script (No Comments) ===")
    print(full_deobfuscated_no_comments)
    
    print("\n=== Deobfuscated Full Script (With Comments) ===")
    print(full_deobfuscated_with_comments)

    if undefined_vars:
        print("\n=== Undefined Variables ===")
        for v in undefined_vars:
            print(f"%{v}%")
    
    return {
        "dictionary": variables,
        "obfuscated": batch_content,
        "deobfuscated": deobfuscated,
        "full_deobfuscated_no_comments": full_deobfuscated_no_comments,
        "full_deobfuscated_with_comments": full_deobfuscated_with_comments,
        "undefined_variables": undefined_vars
    }

if __name__ == "__main__":
    main()
