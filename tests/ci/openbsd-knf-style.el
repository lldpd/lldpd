;;
;; OpenBSD KNF style - batch style converter
;;
;; Copyright (c) 2014,2015 Doug Hogan <doug@openbsd.org>
;; Copyright (c) 2005 Nicholas Marriott <nicm@openbsd.org>
;; Copyright (c) 2022 Vincent Bernat
;;
;; Permission to use, copy, modify, and distribute this software for any
;; purpose with or without fee is hereby granted, provided that the above
;; copyright notice and this permission notice appear in all copies.
;;
;; THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
;; WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
;; MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
;; ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
;; WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
;; ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
;; OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

;; The OpenBSD KNF style is from https://github.com/hogand/openbsd-knf-emacs

;; This function is from nicm@
(defun openbsd-knf-space-indent (langelem)
  "Indents either 4 spaces or none.

This function is from nicm@ and also in gsoares@'s config.
Most useful with c-offset-alist entries that are lists such as
arglist-cont-nonempty"
  (save-excursion
    (goto-char (cdr langelem))
    (setq syntax (car (car (c-guess-basic-syntax))))
    (while (or (eq syntax 'arglist-intro)
	       (or (eq syntax 'arglist-cont)
		   (eq syntax 'arglist-cont-nonempty)))
      (forward-line -1)
      (setq syntax (car (car (c-guess-basic-syntax)))))
    (beginning-of-line)
    (re-search-forward "[^ \t]" (c-point 'eol))
    (goto-char (+ (match-beginning 0) 4))
    (vector (current-column))))

;; OpenBSD KNF that doug@ uses.
(defconst openbsd-knf-style
  '(
    ;; Debugging
    ;; (c-echo-syntactic-information-p . t) ;; display C-c C-s when hit 'tab'
    ;;
    ;; General settings that should be enabled in c-mode
    (indent-tabs-mode . t)      ;; use tabs whenever feasible
    (fill-column . 80)          ;; Assume KNF tries to maintain 80 char lines
    (show-trailing-whitespace . t)  ;; KNF says to not have trailing WS
    (tab-width . 8)             ;; When displaying literal tab, show 8 spaces
    ;; c-mode
    (c-progress-interval . 1)   ;; display progress meter during long indents
    (c-basic-offset . 8)        ;; KNF uses 8 space tabs
    (c-comment-only-line-offset . 0)  ;; don't indent comments extra
    (c-backspace-function . delete-backward-char)
    (c-delete-function . delete-char)
    (c-syntactic-indentation-in-macros . t) ;; indent inside macro defs
    (c-tab-always-indent . t)  ;; indent line: Use C-q 'tab' to insert literal
    (c-continued-statement-offset 0)
    ;; (c-electric-flag . nil)   ;; if you don't like auto-indent
    (c-electric-continued-statement . t)
    ;;
    (c-indent-comments-syntactically-p . nil)
    ;;
    ;; Offsets for the various c-mode symbols.  Offsets are sometimes based
    ;; upon other offsets.  For instance, arglist-intro is the 1st argument
    ;; line.  If you define arglist-cont, it uses arglist-intro plus that.
    ;; c-echo-syntactic-information-p is your friend when debugging indents.
    ;;
    ;; [N] means absolute column.  All the others are relative.
    ;;  0 = no extra indentation.  For literal column 0, use [0]
    ;;  N = extra N spaces.  For literal column N, use [N]
    ;; ++ = c-basic-offset * 2
    ;; -- = c-basic-offset * -2
    ;;  + = c-basic-offset * 1
    ;;  - = c-basic-offset * -1
    ;;  * = c-basic-offset * 0.5
    ;;  / = c-basic-offset * -0.5
    (c-offsets-alist . (
			;; Literal symbols
			(func-decl-cont . 0)        ; C++ style func mod
			(block-open . 0)            ; '{' for block
			(label . [1])               ; goto label in column 1
			(comment-intro . 0)         ; C comment
			(cpp-macro . [0])           ; #define in column 0
			;; Multiline macro symbols
			(cpp-define-intro . [0])    ; first list = column 0
			(cpp-macro-cont . +)        ; add'l lines in macro
			;; Function symbols
			(defun-open . 0)            ; '{' alone for func
			(defun-close . 0)           ; '}' alone for func
			(defun-block-intro . +)     ; first line of func
			(topmost-intro . 0)         ; outermost part
			(topmost-intro-cont . 0)    ; outermost part cont
			(statement . 0)             ; func stmt (already off)
			;; XXX statement-cont should be 4 unless
			;; it is part of a macro, then 8.
			(statement-cont . *)        ; continue stmt
			;; Class symbols.  XXX Should add support since there
			;; is a little C++ in the tree (GNU)
			;; Java
			;; K&R
			(knr-argdecl-intro . +)     ; rare K&R (from KNF)
			(knr-argdecl . 0)           ; add'l indent for rest
			;; Conditional construct symbols
			(block-close . 0)           ; '}' for block
			(statement-block-intro . +) ; stmt in loop/cond
			(substatement . +)          ; non-braced stmt if()
			(substatement-open . 0)     ; '{' in loop/cond
			(substatement-label . [1])  ; goto label in loop/cond
			(do-while-closure . 0)      ; 'while' alone in 'do'
			(else-clause . 0)           ; 'else' when not nested
			;; Brace list symbols
			(brace-list-close . 0)      ; enum/agg list close
			(brace-list-intro . +)      ; 1st line of enum/agg
			(brace-list-entry . 0)      ; add'l indent for entries
			(brace-list-open . 0)       ; enum/agg init open
			;; Switch statement symbols
			(statement-case-open . +)   ; '{' in case
			(statement-case-intro . +)  ; 1st line in case stmt
			(case-label . 0)            ; case label in switch
			;; Paren list symbols
			;; XXX This is typically a list so need to handle it
			;; differently from the rest.  Emacs adds the indents.
			(arglist-intro . openbsd-knf-space-indent) ; 1st line
			(arglist-cont . openbsd-knf-space-indent)
			(arglist-cont-nonempty . openbsd-knf-space-indent)
			(arglist-close . 0)         ; ')' alone
			;; External scope symbols
			(extern-lang-open . [0])    ; '{' alone in 'extern C'
			(extern-lang-close . [0])   ; '}' alone in 'extern C'
			(inextern-lang . +)         ; lines inside 'extern C'
			;; Statement block
			(inexpr-statement . +)))    ; gcc extension stmt expr
    ;; If not specified, the default is "before after".  All variables are
    ;; defined here.
    (c-hanging-braces-alist . (
			       ;; All variables
			       (defun-open before after)  ; function, enum
			       (defun-close before after) ; function
			       (class-open after) ; struct too
			       (class-close before after)
			       (inline-open after)
			       (inline-close before after)
			       (block-open after)
                               (block-close . c-snug-do-while)
			       (statement-cont after)
			       (substatement-open after)
			       (statement-case-open before after)
			       (brace-list-open after)
			       (brace-list-close before close)
			       (brace-list-intro after)
			       (brace-entry-open after)
			       (extern-lang-open after)
			       (extern-lang-close before after)
			       (namespace-open after)           ;; C++
			       (namespace-close before afetr)   ;; C++
			       (module-open after)              ;; CORBA
			       (module-close before after)      ;; CORBA
			       (composition-open after)         ;; CORBA
			       (composition-close before after) ;; CORBA
			       (inexpr-class-open after)
			       (inexpr-class-close before after)
			       (arglist-cont-nonempty before after)))
    ;; Whether to auto-insert newline before/after colon
    (c-hanging-colons-alist . ((case-label after)
                               (label after)
                               (access-label after)  ;; C++
                               (member-init-intro before)
                               (inher-intro)))
    ;; Whether to insert newlines after ';' or ','
    (c-hanging-semi&comma-criteria . (
				      ;; supress newline when next line non-blank
				      c-semi&comma-no-newlines-before-nonblanks
				      ;; suppress newline in paren (for loop etc)
				      c-semi&comma-inside-parenlist
				      ;; supress newline for one liner
				      c-semi&comma-no-newlines-for-oneline-inliners))
    ;; When autonewline mode is enabled, clean up some extra newlines
    (c-cleanup-list . (brace-else-brace    ; } else {
                       brace-elseif-brace  ; } else if {
                       brace-catch-brace   ; } catch (...) {
                       ;; empty-defun-braces ; {} instead of multiple lines
                       defun-close-semi    ; struct: no \n between '}' and ';'
                       list-close-comma    ; remove final comma
                       scope-operator
		       ;; space-before-funcall ; GNU standard
		       ;; compact-empty-funcall ; another GNU standard
		       ;; comment-close-slash ; term comment with slash
		       ))
    ))

(c-add-style "openbsd" openbsd-knf-style)
(dolist (file command-line-args-left)
  (when (not (eq file "--"))
    (save-excursion
      (find-file file)
      (c-mode)
      (c-set-style "openbsd")
      (indent-region (point-min) (point-max) nil)
      (save-buffer))))
