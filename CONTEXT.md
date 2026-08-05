# ONE.OS Edge Connector domeintaal

## Location path

Een **Location path** beschrijft waar een object zich bevindt en volgt de containmentketen `Site → Structure → Space → Asset → Point`. `Building` en `Floor` zijn Structure-types; `Room` en `Zone` zijn Space-types. Een Point wordt verplaatst door het aan een bestaand Asset te koppelen; een Asset wordt verplaatst door het aan een bestaande Space te koppelen. Location-termen zijn geen Pointclassificaties.

## Cloud publication selection

**Cloud publication selection** is de lokale commissioningkeuze die bepaalt welke actieve en beoordeelde Points in een latere cloudfase gepubliceerd mogen worden. Zij veroorzaakt in Fase 2A geen netwerkpublicatie. De effectieve selectie van een Asset, Space of Structure is een tri-state samenvatting van zijn Points. Nieuwe Points blijven standaard `unset` en `unreviewed`. Cloudpublicatie staat los van cloudbediening.

## Point display name

De **Point display name** is een lokale, vrij invoerbare presentatienaam. De Home Assistant-bronnaam blijft als bewijs zichtbaar; de override kan worden teruggezet en wordt nooit naar Home Assistant geschreven.

## Point ontology class

De **Point ontology class** beschrijft de semantische betekenis van een Point en is geen locatie of presentatienaam. ONE.OS slaat de klasse op als Brick-compatible URI. De commissioning-UI biedt een gecontroleerde catalogus van veelgebruikte Brick-klassen plus `Anders…` voor een andere expliciete URI. De bronidentiteit en onbewerkte evidence blijven afzonderlijk bewaard.
