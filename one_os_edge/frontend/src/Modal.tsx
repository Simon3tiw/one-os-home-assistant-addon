import {useEffect, useRef} from 'react'
import type {ReactNode} from 'react'

const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'

export function Modal({
  title,
  onClose,
  children,
  initialFocusRef,
}: {
  title: string
  onClose: () => void
  children: ReactNode
  initialFocusRef?: React.RefObject<HTMLElement>
}) {
  const dialogRef = useRef<HTMLDivElement>(null)
  const previouslyFocused = useRef<Element | null>(null)

  useEffect(() => {
    previouslyFocused.current = document.activeElement
    const root = document.getElementById('app-root')
    root?.setAttribute('inert', 'true')
    root?.setAttribute('aria-hidden', 'true')
    const target = initialFocusRef?.current ?? dialogRef.current
    target?.focus()
    return () => {
      root?.removeAttribute('inert')
      root?.removeAttribute('aria-hidden')
      if (previouslyFocused.current instanceof HTMLElement) {
        previouslyFocused.current.focus()
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function onKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape') {
      event.stopPropagation()
      onClose()
      return
    }
    if (event.key !== 'Tab' || !dialogRef.current) return
    const focusable = Array.from(dialogRef.current.querySelectorAll<HTMLElement>(FOCUSABLE))
    if (focusable.length === 0) return
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  }

  return (
    <div className="modal-overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className="modal"
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        {children}
      </div>
    </div>
  )
}
